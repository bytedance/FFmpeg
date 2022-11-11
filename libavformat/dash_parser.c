/*
 * Dynamic Adaptive Streaming over HTTP demux
 * Copyright (c) 2017 samsamsam@o2.pl based on HLS demux
 * Copyright (c) 2017 Steven Liu
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 * 
 * This file may have been modified by Bytedance Inc. (“Bytedance Modifications”). 
 * All Bytedance Modifications are Copyright 2022 Bytedance Inc.
 */

#include "dash_context.h"
#include "dash_parser.h"
#include <libxml/parser.h>

int add_to_pktbuf(AVPacketList **packet_buffer, AVPacket *pkt,
                         AVPacketList **plast_pktl)
{
    AVPacketList *pktl = av_mallocz(sizeof(AVPacketList));
    if (!pktl){
        av_log(NULL,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
        return AVERROR(ENOMEM);
    }
    pktl->pkt = *pkt;
    if (*packet_buffer)
        (*plast_pktl)->next = pktl;
    else
        *packet_buffer = pktl;

    /* Add the packet in the buffered packet list. */
    *plast_pktl = pktl;
    return 0;
}


int read_from_packet_buffer(AVPacketList **pkt_buffer,
                                   AVPacketList **pkt_buffer_end,
                                   AVPacket      *pkt)
{
    if (!(*pkt_buffer)) {
        return -1;
    }

    AVPacketList *pktl;
    pktl        = *pkt_buffer;
    *pkt        = pktl->pkt;
    *pkt_buffer = pktl->next;
    if (!pktl->next)
        *pkt_buffer_end = NULL;
    av_freep(&pktl);
    return 0;
}


void free_packet_buffer(AVPacketList **pkt_buf, AVPacketList **pkt_buf_end)
{
    while (*pkt_buf) {
        AVPacketList *pktl = *pkt_buf;
        *pkt_buf = pktl->next;
        av_packet_unref(&pktl->pkt);
        av_freep(&pktl);
    }
    *pkt_buf_end = NULL;
}

static int is_http_protocol(const char *url)
{
    if (url == NULL) return 0;
    const char * name = avio_find_protocol_name(url);
    if (name == NULL) return 0;
    return av_strstart(name, "http", NULL);
}

static int aligned_value(int val)
{
    return ((val + 0x3F) >> 6) << 6;
}

static uint64_t get_time_in_sec_default(void)
{
    return  av_gettime() / 1000000;
}

static uint64_t get_time_in_sec_with_datetime(const char *datetime)
{
    struct tm timeinfo;
    int year = 0;
    int month = 0;
    int day = 0;
    int hour = 0;
    int minute = 0;
    int ret = 0;
    float second = 0.0;

    /* ISO-8601 date parser */
    if (!datetime)
        return 0;

    ret = sscanf(datetime, "%d-%d-%dT%d:%d:%fZ", &year, &month, &day, &hour, &minute, &second);
    /* year, month, day, hour, minute, second  6 arguments */
    if (ret != 6) {
        av_log(NULL, AV_LOG_WARNING, "get_time_in_sec_with_datetime get a wrong time format\n");
    }
    timeinfo.tm_year = year - 1900;
    timeinfo.tm_mon  = month - 1;
    timeinfo.tm_mday = day;
    timeinfo.tm_hour = hour;
    timeinfo.tm_min  = minute;
    timeinfo.tm_sec  = (int)second;

    return av_timegm(&timeinfo);
}

static uint32_t get_time_in_sec_with_duration(const char *duration)
{
    /* ISO-8601 duration parser */
    uint32_t days = 0;
    uint32_t hours = 0;
    uint32_t mins = 0;
    uint32_t secs = 0;
    int size = 0;
    float value = 0;
    char type = '\0';
    const char *ptr = duration;

    while (*ptr) {
        if (*ptr == 'P' || *ptr == 'T') {
            ptr++;
            continue;
        }

        if (sscanf(ptr, "%f%c%n", &value, &type, &size) != 2) {
            av_log(NULL, AV_LOG_WARNING, "get_time_in_sec_with_duration get a wrong time format\n");
            return 0; /* parser error */
        }
        switch (type) {
            case 'D':
                days = (uint32_t)value;
                break;
            case 'H':
                hours = (uint32_t)value;
                break;
            case 'M':
                mins = (uint32_t)value;
                break;
            case 'S':
                secs = (uint32_t)value;
                break;
            default:
                // handle invalid type
                break;
        }
        ptr += size;
    }
    return  ((days * 24 + hours) * 60 + mins) * 60 + secs;
}

int64_t get_segment_start_time_based_on_timeline(struct representation *pls, int64_t cur_seq_no)
{
    int64_t start_time = 0;
    int64_t i = 0;
    int64_t j = 0;
    int64_t num = 0;

    pthread_mutex_lock(&pls->async_update_lock);
    if (pls->first_seq_no > 0)
        num = pls->first_seq_no;

    if (pls->n_timelines) {
        for (i = 0; i < pls->n_timelines; i++) {
            if (pls->timelines[i]->starttime > 0) {
                start_time = pls->timelines[i]->starttime;
            }
            if (num == cur_seq_no)
                goto finish;

            start_time += pls->timelines[i]->duration;
            for (j = 0; j < pls->timelines[i]->repeat; j++) {
                num++;
                if (num == cur_seq_no)
                    goto finish;
                start_time += pls->timelines[i]->duration;
            }
            num++;
        }
    }
    finish:
    pthread_mutex_unlock(&pls->async_update_lock);
    return start_time;
}

char *get_cenc_default_kid(const char *kid)
{
    const char *prefix = "urn:marlin:kid:";
    char *cenc_default_kid = NULL;
    char *ptr = NULL;
    size_t len = 0;

    if (!kid) {
        return NULL;
    }

    len = strlen(prefix) + strlen(kid) + 1;
    cenc_default_kid = av_mallocz(len);
    if (!cenc_default_kid) {
        return NULL;
    }

    av_strlcpy(cenc_default_kid, prefix, len);

    ptr = cenc_default_kid + strlen(prefix);
    while (*kid != '\0') {
        if (*kid != '-') {
            *ptr++ = *kid;
        }
        kid++;
    }
    *ptr = '\0';

    return cenc_default_kid;
}

int64_t calc_next_seg_no_from_timelines(struct representation *pls, int64_t cur_time)
{
    int64_t i = 0;
    int64_t j = 0;
    int64_t num = 0;
    int64_t start_time = 0;

    pthread_mutex_lock(&pls->async_update_lock);
    for (i = 0; i < pls->n_timelines; i++) {
        if (pls->timelines[i]->starttime > 0) {
            start_time = pls->timelines[i]->starttime;
        }
        if (start_time > cur_time)
            goto finish;

        start_time += pls->timelines[i]->duration;
        for (j = 0; j < pls->timelines[i]->repeat; j++) {
            num++;
            if (start_time > cur_time)
                goto finish;
            start_time += pls->timelines[i]->duration;
        }
        num++;
    }
    pthread_mutex_unlock(&pls->async_update_lock);
    return -1;

    finish:
    pthread_mutex_unlock(&pls->async_update_lock);
    return num;
}

void free_fragment(struct fragment **seg)
{
    if (!(*seg)) {
        return;
    }
    av_freep(&(*seg)->url);
    av_freep(seg);
}

void free_fragment_list(struct representation *pls)
{
    int i;

    for (i = 0; i < pls->n_fragments; i++) {
        free_fragment(&pls->fragments[i]);
    }
    av_freep(&pls->fragments);
    pls->n_fragments = 0;
}

void free_timelines_list(struct representation *pls)
{
    int i;

    for (i = 0; i < pls->n_timelines; i++) {
        av_freep(&pls->timelines[i]);
    }
    av_freep(&pls->timelines);
    pls->n_timelines = 0;
}

static void tt_format_io_close(AVFormatContext *s, AVIOContext **pb) {
    if (*pb)
        s->io_close(s, *pb);
    *pb = NULL;
}

void free_representation(struct representation *pls)
{
    free_fragment_list(pls);
    free_timelines_list(pls);
    free_fragment(&pls->cur_seg);
    free_fragment(&pls->init_section);
    av_dict_free(&pls->avio_opts);
    av_freep(&pls->init_sec_buf);
    av_freep(&pls->pb.buffer);
    if (pls->input)
        tt_format_io_close(pls->parent, &pls->input);
    if (pls->ctx) {
        pls->ctx->pb = NULL;
        avformat_close_input(&pls->ctx);
    }
    av_freep(&pls->url_template);
    av_freep(&pls->cenc_default_kid);
    pthread_mutex_destroy(&pls->async_update_lock);
    av_freep(&pls);
}

void free_video_list(DASHContext *c)
{
    int i;
    for (i = 0; i < c->n_videos; i++) {
        struct representation *pls = c->videos[i];
        free_representation(pls);
    }
    av_freep(&c->videos);
    c->n_videos = 0;
}

void free_audio_list(DASHContext *c)
{
    int i;
    for (i = 0; i < c->n_audios; i++) {
        struct representation *pls = c->audios[i];
        free_representation(pls);
    }
    av_freep(&c->audios);
    c->n_audios = 0;
}


static char *get_content_url(xmlNodePtr *baseurl_nodes,
                             int n_baseurl_nodes,
                             int max_url_size,
                             char *rep_id_val,
                             char *rep_bandwidth_val,
                             char *val)
{
    int i;
    char *text;
    char *url = NULL;
    char *tmp_str = av_mallocz(max_url_size);
    char *tmp_str_2 = av_mallocz(max_url_size);

    if (!tmp_str || !tmp_str_2) {
        return NULL;
    }

    for (i = 0; i < n_baseurl_nodes; ++i) {
        if (baseurl_nodes[i] &&
            baseurl_nodes[i]->children &&
            baseurl_nodes[i]->children->type == XML_TEXT_NODE) {
            text = (char*) xmlNodeGetContent(baseurl_nodes[i]->children);
            if (text) {
                memset(tmp_str_2, 0, max_url_size);
                tt_make_absolute_url(tmp_str_2, max_url_size, tmp_str, text);
                av_strlcpy(tmp_str, tmp_str_2, max_url_size);
                xmlFree(text);
            }
        }
    }

    if (val)
        av_strlcat(tmp_str, (const char*)val, max_url_size);

    if (rep_id_val) {
        url = av_strireplace(tmp_str, "$RepresentationID$", (const char*)rep_id_val);
        if (!url) {
            goto end;
        }
        av_strlcpy(tmp_str, url, max_url_size);
    }
    if (rep_bandwidth_val && tmp_str[0] != '\0') {
        // free any previously assigned url before reassigning
        av_free(url);
        url = av_strireplace(tmp_str, "$Bandwidth$", (const char*)rep_bandwidth_val);
        if (!url) {
            goto end;
        }
    }
    end:
    av_free(tmp_str);
    av_free(tmp_str_2);
    return url;
}

static char *get_val_from_nodes_tab(xmlNodePtr *nodes, const int n_nodes, const char *attrname)
{
    int i;
    char *val;

    for (i = 0; i < n_nodes; ++i) {
        if (nodes[i]) {
            val = (char*) xmlGetProp(nodes[i], (const xmlChar *)attrname);
            if (val)
                return val;
        }
    }

    return NULL;
}

static xmlNodePtr find_child_node_by_name(xmlNodePtr rootnode, const char *nodename)
{
    xmlNodePtr node = rootnode;
    if (!node) {
        return NULL;
    }

    node = xmlFirstElementChild(node);
    while (node) {
        if (!av_strcasecmp((const char *)node->name, nodename)) {
            return node;
        }
        node = xmlNextElementSibling(node);
    }
    return NULL;
}

enum AVMediaType get_content_type(xmlNodePtr node)
{
    enum AVMediaType type = AVMEDIA_TYPE_UNKNOWN;
    int i = 0;
    const char *attr;
    char *val = NULL;

    if (node) {
        for (i = 0; i < 2; i++) {
            attr = i ? "mimeType" : "contentType";
            val = (char*) xmlGetProp(node, (const xmlChar*)attr);
            if (val) {
                if (av_stristr((const char *)val, "video")) {
                    type = AVMEDIA_TYPE_VIDEO;
                } else if (av_stristr((const char *)val, "audio")) {
                    type = AVMEDIA_TYPE_AUDIO;
                }
                xmlFree(val);
            }
        }
    }
    return type;
}

struct fragment * get_Fragment(char *range)
{
    struct fragment * seg =  av_mallocz(sizeof(struct fragment));

    if (!seg)
        return NULL;

    seg->size = -1;
    if (range) {
        char *str_end_offset;
        char *str_offset = av_strtok(range, "-", &str_end_offset);
        seg->url_offset = strtoll(str_offset, NULL, 10);
        seg->size = strtoll(str_end_offset, NULL, 10) - seg->url_offset + 1;
    }

    return seg;
}

static int parse_manifest_segmenturlnode(DASHContext *c, struct representation *rep,
                                         xmlNodePtr fragmenturl_node,
                                         xmlNodePtr *baseurl_nodes,
                                         char *rep_id_val,
                                         char *rep_bandwidth_val)
{
    char *initialization_val = NULL;
    char *media_val = NULL;
    char *range_val = NULL;
    int max_url_size = c ? c->max_url_size: MAX_URL_SIZE;

    if (!av_strcasecmp((const char *)fragmenturl_node->name, (const char *)"Initialization")) {
        initialization_val = (char*) xmlGetProp(fragmenturl_node, (const xmlChar*)"sourceURL");
        range_val = (char*) xmlGetProp(fragmenturl_node, (const xmlChar*)"range");
        if (initialization_val || range_val) {
            rep->init_section = get_Fragment(range_val);
            if (!rep->init_section) {
                xmlFree(initialization_val);
                xmlFree(range_val);
                return AVERROR(ENOMEM);
            }
            rep->init_section->url = get_content_url(baseurl_nodes, 4,
                                                     max_url_size,
                                                     rep_id_val,
                                                     rep_bandwidth_val,
                                                     initialization_val);

            if (!rep->init_section->url) {
                av_free(rep->init_section);
                xmlFree(initialization_val);
                xmlFree(range_val);
                return AVERROR(ENOMEM);
            }
            xmlFree(initialization_val);
            xmlFree(range_val);
        }
    } else if (!av_strcasecmp((const char *)fragmenturl_node->name, (const char *)"SegmentURL")) {
        media_val = (char*) xmlGetProp(fragmenturl_node, (const xmlChar*)"media");
        range_val = (char*) xmlGetProp(fragmenturl_node, (const xmlChar*)"mediaRange");
        if (media_val || range_val) {
            struct fragment *seg = get_Fragment(range_val);
            if (!seg) {
                xmlFree(media_val);
                xmlFree(range_val);
                return AVERROR(ENOMEM);
            }
            seg->url = get_content_url(baseurl_nodes, 4,
                                       max_url_size,
                                       rep_id_val,
                                       rep_bandwidth_val,
                                       media_val);
            if (!seg->url) {
                av_free(seg);
                xmlFree(media_val);
                xmlFree(range_val);
                return AVERROR(ENOMEM);
            }
            av_dynarray_add(&rep->fragments, &rep->n_fragments, seg);
            xmlFree(media_val);
            xmlFree(range_val);
        }
    }

    return 0;
}

static int parse_manifest_segmenttimeline(struct representation *rep,
                                          xmlNodePtr fragment_timeline_node)
{
    xmlAttrPtr attr = NULL;
    char *val  = NULL;

    if (!av_strcasecmp((const char *)fragment_timeline_node->name, (const char *)"S")) {
        struct timeline *tml = av_mallocz(sizeof(struct timeline));
        if (!tml) {
            return AVERROR(ENOMEM);
        }
        attr = fragment_timeline_node->properties;
        while (attr) {
            val = (char*)xmlGetProp(fragment_timeline_node, attr->name);

            if (!val) {
                av_log(NULL, AV_LOG_WARNING, "parse_manifest_segmenttimeline attr->name = %s val is NULL\n", attr->name);
                continue;
            }

            if (!av_strcasecmp((const char *)attr->name, (const char *)"t")) {
                tml->starttime = (int64_t)strtoll(val, NULL, 10);
            } else if (!av_strcasecmp((const char *)attr->name, (const char *)"r")) {
                tml->repeat =(int64_t) strtoll(val, NULL, 10);
            } else if (!av_strcasecmp((const char *)attr->name, (const char *)"d")) {
                tml->duration = (int64_t)strtoll(val, NULL, 10);
            }
            attr = attr->next;
            xmlFree(val);
        }
        av_dynarray_add(&rep->timelines, &rep->n_timelines, tml);
    }

    return 0;
}

static int resolve_content_path(const char *url, int *max_url_size, xmlNodePtr *baseurl_nodes, int n_baseurl_nodes) {

    char *tmp_str = NULL;
    char *path = NULL;
    char *mpdName = NULL;
    xmlNodePtr node = NULL;
    char *baseurl = NULL;
    char *root_url = NULL;
    char *text = NULL;
    char *tmp = NULL;

    int isRootHttp = 0;
    char token ='/';
    int start =  0;
    int rootId = 0;
    int updated = 0;
    int size = 0;
    int i;
    int tmp_max_url_size = strlen(url) + 1;
    for (i = n_baseurl_nodes-1; i >= 0 ; i--) {
        text = (char*) xmlNodeGetContent(baseurl_nodes[i]);
        if (!text)
            continue;
        tmp_max_url_size += strlen(text);
        if (is_http_protocol(text)) {
            xmlFree(text);
            break;
        }
        xmlFree(text);
    }

    tmp_max_url_size = aligned_value(tmp_max_url_size);
    text = av_mallocz(tmp_max_url_size);
    if (!text) {
        updated = AVERROR(ENOMEM);
        goto end;
    }
    av_strlcpy(text, url, strlen(url)+1);
    tmp = text;
    while ((mpdName = av_strtok(tmp, "/", &tmp)))  {
        size = strlen(mpdName);
    }
    av_free(text);

    path = av_mallocz(tmp_max_url_size);
    tmp_str = av_mallocz(tmp_max_url_size);
    if (!tmp_str || !path) {
        updated = AVERROR(ENOMEM);
        goto end;
    }

    av_strlcpy (path, url, strlen(url) - size + 1);
    for (rootId = n_baseurl_nodes - 1; rootId > 0; rootId --) {
        if (!(node = baseurl_nodes[rootId])) {
            continue;
        }
        text = (char*) xmlNodeGetContent(node);
        if (text) {
            if (is_http_protocol(text)) {
                xmlFree(text);
                break;
            }
            xmlFree(text);
        }
    }

    node = baseurl_nodes[rootId];
    baseurl = (char*) xmlNodeGetContent(node);
    root_url = (av_strcasecmp(baseurl, "")) ? baseurl : path;
    if (node) {
        xmlNodeSetContent(node, (const xmlChar *)root_url);
        updated = 1;
    }

    size = strlen(root_url);
    isRootHttp = is_http_protocol(root_url);

    if (root_url[size - 1] != token) {
        av_strlcat(root_url, "/", size + 2);
        size += 2;
    }

    for (i = 0; i < n_baseurl_nodes; ++i) {
        if (i == rootId) {
            continue;
        }
        text = (char*) xmlNodeGetContent(baseurl_nodes[i]);
        if (text) {
            memset(tmp_str, 0, strlen(tmp_str));
            if (!is_http_protocol(text) && isRootHttp) {
                av_strlcpy(tmp_str, root_url, size + 1);
            }
            start = (text[0] == token);
            av_strlcat(tmp_str, text + start, tmp_max_url_size);
            xmlNodeSetContent(baseurl_nodes[i], (const xmlChar *)tmp_str);
            updated = 1;
            xmlFree(text);
        }
    }

    end:
    if (tmp_max_url_size > *max_url_size) {
        *max_url_size = tmp_max_url_size;
    }
    av_free(path);
    av_free(tmp_str);
    xmlFree(baseurl);
    return updated;

}

static int parse_manifest_representation(DASHContext *c, const char *url,
                                         xmlNodePtr node,
                                         xmlNodePtr adaptionset_node,
                                         xmlNodePtr mpd_baseurl_node,
                                         xmlNodePtr period_baseurl_node,
                                         xmlNodePtr period_segmenttemplate_node,
                                         xmlNodePtr period_segmentlist_node,
                                         xmlNodePtr fragment_template_node,
                                         xmlNodePtr content_component_node,
                                         xmlNodePtr adaptionset_baseurl_node,
                                         xmlNodePtr adaptionset_segmentlist_node,
                                         xmlNodePtr adaptionset_contentprotection_node)
{
    int32_t ret = 0;
    int32_t audio_rep_idx = 0;
    int32_t video_rep_idx = 0;

    struct representation *rep = NULL;
    struct fragment *seg = NULL;
    xmlNodePtr representation_segmentbase_node = NULL;
    xmlNodePtr segmentbase_initialization_node = NULL;
    xmlNodePtr representation_segmenttemplate_node = NULL;
    xmlNodePtr representation_baseurl_node = NULL;
    xmlNodePtr representation_segmentlist_node = NULL;
    xmlNodePtr representation_contentprotection_node = NULL;
    xmlNodePtr contentprotection_tab[2];
    xmlNodePtr segmentlists_tab[2];
    xmlNodePtr fragment_timeline_node = NULL;
    xmlNodePtr fragment_templates_tab[5];
    char *initialization_range_val = NULL;
    char *index_range_val = NULL;
    char *duration_val = NULL;
    char *presentation_timeoffset_val = NULL;
    char *startnumber_val = NULL;
    char *timescale_val = NULL;
    char *initialization_val = NULL;
    char *media_val = NULL;
    char *cenc_default_kid_val = NULL;
    xmlNodePtr baseurl_nodes[4];
    xmlNodePtr representation_node = node;
    char *rep_id_val = (char*)xmlGetProp(representation_node, (const xmlChar*)"id");
    char *rep_bandwidth_val = (char*)xmlGetProp(representation_node, (const xmlChar*)"bandwidth");
    char *rep_framerate_val = (char*)xmlGetProp(representation_node, (const xmlChar*)"frameRate");
    enum AVMediaType type = AVMEDIA_TYPE_UNKNOWN;
    int rep_bandwidth_len = 0;
    int rep_framerate_len = 0;
    if (rep_bandwidth_val) {
        rep_bandwidth_len = strlen(rep_bandwidth_val);
    }
    if (rep_framerate_val) {
        rep_framerate_len = strlen(rep_framerate_val);
    }

    // try get information from representation
    if (type == AVMEDIA_TYPE_UNKNOWN)
        type = get_content_type(representation_node);
    // try get information from contentComponen
    if (type == AVMEDIA_TYPE_UNKNOWN)
        type = get_content_type(content_component_node);
    // try get information from adaption set
    if (type == AVMEDIA_TYPE_UNKNOWN)
        type = get_content_type(adaptionset_node);
    if (type == AVMEDIA_TYPE_UNKNOWN) {
        av_log(c, AV_LOG_ERROR, "skip not supported representation type\n");
    } else if (type == AVMEDIA_TYPE_VIDEO || type == AVMEDIA_TYPE_AUDIO) {
        // convert selected representation to our internal struct
        rep = av_mallocz(sizeof(struct representation));
        if (!rep) {
            ret = AVERROR(ENOMEM);
            goto end;
        }

        pthread_mutex_init(&rep->async_update_lock, NULL);

        representation_segmenttemplate_node = find_child_node_by_name(representation_node, "SegmentTemplate");
        representation_baseurl_node = find_child_node_by_name(representation_node, "BaseURL");
        representation_segmentlist_node = find_child_node_by_name(representation_node, "SegmentList");
        representation_contentprotection_node = find_child_node_by_name(representation_node, "ContentProtection");

        baseurl_nodes[0] = mpd_baseurl_node;
        baseurl_nodes[1] = period_baseurl_node;
        baseurl_nodes[2] = adaptionset_baseurl_node;
        baseurl_nodes[3] = representation_baseurl_node;

        ret = resolve_content_path(url, &c->max_url_size, baseurl_nodes, 4);

        c->max_url_size = aligned_value(c->max_url_size  + strlen(rep_id_val) + rep_bandwidth_len);
        if (ret == AVERROR(ENOMEM) || ret == 0) {
            goto end;
        }
        if (representation_segmenttemplate_node || fragment_template_node || period_segmenttemplate_node) {
            fragment_timeline_node = NULL;
            fragment_templates_tab[0] = representation_segmenttemplate_node;
            fragment_templates_tab[1] = adaptionset_segmentlist_node;
            fragment_templates_tab[2] = fragment_template_node;
            fragment_templates_tab[3] = period_segmenttemplate_node;
            fragment_templates_tab[4] = period_segmentlist_node;

            presentation_timeoffset_val = get_val_from_nodes_tab(fragment_templates_tab, 4, "presentationTimeOffset");
            duration_val = get_val_from_nodes_tab(fragment_templates_tab, 4, "duration");
            startnumber_val = get_val_from_nodes_tab(fragment_templates_tab, 4, "startNumber");
            timescale_val = get_val_from_nodes_tab(fragment_templates_tab, 4, "timescale");
            initialization_val = get_val_from_nodes_tab(fragment_templates_tab, 4, "initialization");
            media_val = get_val_from_nodes_tab(fragment_templates_tab, 4, "media");

            if (initialization_val) {
                rep->init_section = av_mallocz(sizeof(struct fragment));
                if (!rep->init_section) {
                    av_free(rep);
                    ret = AVERROR(ENOMEM);
                    goto end;
                }
                c->max_url_size = aligned_value(c->max_url_size  + strlen(initialization_val));
                rep->init_section->url = get_content_url(baseurl_nodes, 4,  c->max_url_size, rep_id_val, rep_bandwidth_val, initialization_val);
                if (!rep->init_section->url) {
                    av_free(rep->init_section);
                    av_free(rep);
                    ret = AVERROR(ENOMEM);
                    goto end;
                }
                rep->init_section->size = -1;
                xmlFree(initialization_val);
            }

            if (media_val) {
                c->max_url_size = aligned_value(c->max_url_size  + strlen(media_val));
                rep->url_template = get_content_url(baseurl_nodes, 4, c->max_url_size, rep_id_val, rep_bandwidth_val, media_val);
                xmlFree(media_val);
            }

            if (presentation_timeoffset_val) {
                rep->presentation_timeoffset = (int64_t) strtoll(presentation_timeoffset_val, NULL, 10);
                xmlFree(presentation_timeoffset_val);
            }
            if (duration_val) {
                rep->fragment_duration = (int64_t) strtoll(duration_val, NULL, 10);
                xmlFree(duration_val);
            }
            if (timescale_val) {
                rep->fragment_timescale = (int64_t) strtoll(timescale_val, NULL, 10);
                xmlFree(timescale_val);
            }
            if (startnumber_val) {
                rep->first_seq_no = (int64_t) strtoll(startnumber_val, NULL, 10);
                xmlFree(startnumber_val);
            }

            fragment_timeline_node = find_child_node_by_name(representation_segmenttemplate_node, "SegmentTimeline");

            if (!fragment_timeline_node)
                fragment_timeline_node = find_child_node_by_name(fragment_template_node, "SegmentTimeline");
            if (!fragment_timeline_node)
                fragment_timeline_node = find_child_node_by_name(adaptionset_segmentlist_node, "SegmentTimeline");
            if (!fragment_timeline_node)
                fragment_timeline_node = find_child_node_by_name(period_segmentlist_node, "SegmentTimeline");
            if (fragment_timeline_node) {
                fragment_timeline_node = xmlFirstElementChild(fragment_timeline_node);
                while (fragment_timeline_node) {
                    ret = parse_manifest_segmenttimeline(rep, fragment_timeline_node);
                    if (ret < 0) {
                        return ret;
                    }
                    fragment_timeline_node = xmlNextElementSibling(fragment_timeline_node);
                }
            } else {
                rep->is_need_check_seek = 1;
            }
        } else if (representation_baseurl_node && !representation_segmentlist_node) {
            representation_segmentbase_node = find_child_node_by_name(representation_node, "SegmentBase");
            if (representation_segmentbase_node) {
                rep->is_segmentbase = 1;
                // open with offset is not supported on local mpd
                if (is_http_protocol(url)) {
                    segmentbase_initialization_node = find_child_node_by_name(representation_segmentbase_node, "Initialization");
                    if (segmentbase_initialization_node) {
                        initialization_range_val = (char*)xmlGetProp(segmentbase_initialization_node, (const xmlChar*)"range");
                    }
                    index_range_val = (char*)xmlGetProp(representation_segmentbase_node, (const xmlChar*)"indexRange");
                }
            }
            if (initialization_range_val) {
                rep->init_section = get_Fragment(initialization_range_val);
                if (rep->init_section && rep->init_section->url_offset == 0) {
                    if (index_range_val) {
                        char *str_end_offset;
                        char *str_offset = av_strtok(index_range_val, "-", &str_end_offset);
                        if (rep->init_section->size == strtoll(str_offset, NULL, 10)) {
                            rep->init_section->size = strtoll(str_end_offset, NULL, 10) + 1;
                        }
                        xmlFree(index_range_val);
                    }
                    rep->init_section->url = get_content_url(baseurl_nodes, 4, c->max_url_size, rep_id_val, rep_bandwidth_val, NULL);
                    if (!rep->init_section->url) {
                        free_fragment(&rep->init_section);
                    }
                } else {
                    free_fragment(&rep->init_section);
                }
                xmlFree(initialization_range_val);
            }
            seg = av_mallocz(sizeof(struct fragment));
            if (!seg) {
                ret = AVERROR(ENOMEM);
                goto end;
            }
            seg->url = get_content_url(baseurl_nodes, 4, c->max_url_size, rep_id_val, rep_bandwidth_val, NULL);
            if (!seg->url) {
                av_free(seg);
                ret = AVERROR(ENOMEM);
                goto end;
            }
            seg->url_offset = rep->init_section ? rep->init_section->size : 0;
            seg->size = -1;
            av_dynarray_add(&rep->fragments, &rep->n_fragments, seg);
        } else if (representation_segmentlist_node) {
            xmlNodePtr fragmenturl_node = NULL;
            segmentlists_tab[0] = representation_segmentlist_node;
            segmentlists_tab[1] = adaptionset_segmentlist_node;

            duration_val = get_val_from_nodes_tab(segmentlists_tab, 2, "duration");
            timescale_val = get_val_from_nodes_tab(segmentlists_tab, 2, "timescale");
            if (duration_val) {
                rep->fragment_duration = (int64_t) strtoll(duration_val, NULL, 10);
                xmlFree(duration_val);
            }
            if (timescale_val) {
                rep->fragment_timescale = (int64_t) strtoll(timescale_val, NULL, 10);
                xmlFree(timescale_val);
            }
            fragmenturl_node = xmlFirstElementChild(representation_segmentlist_node);
            while (fragmenturl_node) {
                ret = parse_manifest_segmenturlnode(c, rep, fragmenturl_node,
                                                    baseurl_nodes,
                                                    rep_id_val,
                                                    rep_bandwidth_val);
                if (ret < 0) {
                    return ret;
                }
                fragmenturl_node = xmlNextElementSibling(fragmenturl_node);
            }

            fragment_timeline_node = find_child_node_by_name(representation_segmenttemplate_node, "SegmentTimeline");

            if (!fragment_timeline_node)
                fragment_timeline_node = find_child_node_by_name(fragment_template_node, "SegmentTimeline");
            if (!fragment_timeline_node)
                fragment_timeline_node = find_child_node_by_name(adaptionset_segmentlist_node, "SegmentTimeline");
            if (!fragment_timeline_node)
                fragment_timeline_node = find_child_node_by_name(period_segmentlist_node, "SegmentTimeline");
            if (fragment_timeline_node) {
                fragment_timeline_node = xmlFirstElementChild(fragment_timeline_node);
                while (fragment_timeline_node) {
                    ret = parse_manifest_segmenttimeline(rep, fragment_timeline_node);
                    if (ret < 0) {
                        return ret;
                    }
                    fragment_timeline_node = xmlNextElementSibling(fragment_timeline_node);
                }
            }
        } else {
            free_representation(rep);
            rep = NULL;
            av_log(c, AV_LOG_ERROR, "Unknown format of Representation node id[%s] \n", (const char *)rep_id_val);
        }

        contentprotection_tab[0] = adaptionset_contentprotection_node;
        contentprotection_tab[1] = representation_contentprotection_node;
        cenc_default_kid_val = get_val_from_nodes_tab(contentprotection_tab, 2, "default_KID");
        if (cenc_default_kid_val) {
            rep->cenc_default_kid = get_cenc_default_kid(cenc_default_kid_val);
            xmlFree(cenc_default_kid_val);
        }
#if CONFIG_DRM
        if (rep->cenc_default_kid) {
            c->drm_ctx = (void *) (intptr_t) c->drm_aptr;
            if (c->drm_ctx && (av_drm_open(c->drm_ctx, rep->cenc_default_kid) != 0)) {
                av_error(c, AVERROR_DRM_OPEN_FAILED, "drm open failed\n");
                if (c->drm_aptr == 0) {
                    av_drm_close(c->drm_ctx);
                    av_freep(&c->drm_ctx);
                }
                c->drm_ctx = NULL;
            }
        }
#endif
        if (rep) {
            rep->is_opened = 0;
            rep->seek_pos = -1;
            rep->seek_flags = -1;
            rep->is_seeking = 0;
            if (rep->fragment_duration > 0 && !rep->fragment_timescale)
                rep->fragment_timescale = 1;
            rep->bandwidth = rep_bandwidth_val ? atoi(rep_bandwidth_val) : 0;
            strncpy(rep->id, rep_id_val ? rep_id_val : "", sizeof(rep->id));
            rep->framerate = av_make_q(0, 0);
            if (type == AVMEDIA_TYPE_VIDEO && rep_framerate_val) {
                ret = av_parse_video_rate(&rep->framerate, rep_framerate_val);
                if (ret < 0)
                    av_log(c, AV_LOG_VERBOSE, "Ignoring invalid frame rate '%s'\n", rep_framerate_val);
            }
            rep->type = type;
            if (type == AVMEDIA_TYPE_VIDEO) {
                rep->rep_idx = video_rep_idx;
                av_dynarray_add(&c->videos, &c->n_videos, rep);
            } else {
                rep->rep_idx = audio_rep_idx;
                av_dynarray_add(&c->audios, &c->n_audios, rep);
            }
            av_dict_copy(&(rep->avio_opts), c->avio_opts, 0);
        }
    }

    video_rep_idx += type == AVMEDIA_TYPE_VIDEO;
    audio_rep_idx += type == AVMEDIA_TYPE_AUDIO;

    end:
    if (rep_id_val)
        xmlFree(rep_id_val);
    if (rep_bandwidth_val)
        xmlFree(rep_bandwidth_val);
    if (rep_framerate_val)
        xmlFree(rep_framerate_val);

    return ret;
}

static int parse_manifest_adaptationset(DASHContext *c, const char *url,
                                        xmlNodePtr adaptionset_node,
                                        xmlNodePtr mpd_baseurl_node,
                                        xmlNodePtr period_baseurl_node,
                                        xmlNodePtr period_segmenttemplate_node,
                                        xmlNodePtr period_segmentlist_node)
{
    int ret = 0;
    xmlNodePtr fragment_template_node = NULL;
    xmlNodePtr content_component_node = NULL;
    xmlNodePtr adaptionset_baseurl_node = NULL;
    xmlNodePtr adaptionset_segmentlist_node = NULL;
    xmlNodePtr adaptionset_contentprotection_node = NULL;
    xmlNodePtr node = NULL;

    node = xmlFirstElementChild(adaptionset_node);
    while (node) {
        if (!av_strcasecmp((const char *)node->name, (const char *)"SegmentTemplate")) {
            fragment_template_node = node;
        } else if (!av_strcasecmp((const char *)node->name, (const char *)"ContentComponent")) {
            content_component_node = node;
        } else if (!av_strcasecmp((const char *)node->name, (const char *)"BaseURL")) {
            adaptionset_baseurl_node = node;
        } else if (!av_strcasecmp((const char *)node->name, (const char *)"SegmentList")) {
            adaptionset_segmentlist_node = node;
        } else if (!av_strcasecmp((const char *)node->name, (const char *)"ContentProtection")) {
            adaptionset_contentprotection_node = node;
        } else if (!av_strcasecmp((const char *)node->name, (const char *)"Representation")) {
            ret = parse_manifest_representation(c, url, node,
                                                adaptionset_node,
                                                mpd_baseurl_node,
                                                period_baseurl_node,
                                                period_segmenttemplate_node,
                                                period_segmentlist_node,
                                                fragment_template_node,
                                                content_component_node,
                                                adaptionset_baseurl_node,
                                                adaptionset_segmentlist_node,
                                                adaptionset_contentprotection_node);
            if (ret < 0) {
                return ret;
            }
        }
        node = xmlNextElementSibling(node);
    }
    return 0;
}


int64_t calc_min_seg_no(DASHContext *c, struct representation *pls)
{
    int64_t num = 0;

    if (c->is_live && pls->fragment_duration) {
        num = pls->first_seq_no + (((get_time_in_sec_default() - c->availability_start_time) - c->time_shift_buffer_depth) * pls->fragment_timescale) / pls->fragment_duration;
    } else {
        num = pls->first_seq_no;
    }
    return num;
}

int64_t calc_max_seg_no(struct representation *pls, DASHContext *c)
{
    int64_t num = 0;

    pthread_mutex_lock(&pls->async_update_lock);
    if (pls->n_fragments) {
        num = pls->first_seq_no + pls->n_fragments - 1;
    } else if (pls->n_timelines) {
        int i = 0;
        num = pls->first_seq_no + pls->n_timelines - 1;
        for (i = 0; i < pls->n_timelines; i++) {
            num += pls->timelines[i]->repeat;
        }
    } else if (c->is_live && pls->fragment_duration) {
        num = pls->first_seq_no + (((get_time_in_sec_default() - c->availability_start_time)) * pls->fragment_timescale) / pls->fragment_duration;
    } else if (pls->fragment_duration) {
        num = pls->first_seq_no + av_rescale_rnd(c->media_presentation_duration, pls->fragment_timescale, pls->fragment_duration, AV_ROUND_UP) - 1;
    }
    pthread_mutex_unlock(&pls->async_update_lock);

    return num;
}

void copy_init_section(struct representation *rep_dest, struct representation *rep_src) {
    *rep_dest->init_section = *rep_src->init_section;
    rep_dest->init_sec_buf = av_mallocz(rep_src->init_sec_buf_size);
    memcpy(rep_dest->init_sec_buf, rep_src->init_sec_buf, rep_src->init_sec_data_len);
    rep_dest->init_sec_buf_size = rep_src->init_sec_buf_size;
    rep_dest->init_sec_data_len = rep_src->init_sec_data_len;
    rep_dest->cur_timestamp = rep_src->cur_timestamp;
}

void prepare_init_sec_buf(struct representation *pls) {
    static const int max_init_section_size = 1024 * 1024;
    int64_t sec_size;
    int64_t urlsize;
    if (pls->init_section->size >= 0)
        sec_size = pls->init_section->size;
    else if ((urlsize = avio_size(pls->input)) >= 0)
        sec_size = urlsize;
    else
        sec_size = max_init_section_size;

    av_log(pls->parent, AV_LOG_DEBUG,
           "Downloading an initialization section of size %"PRId64"\n",
           sec_size);

    sec_size = FFMIN(sec_size, max_init_section_size);

    av_fast_malloc(&pls->init_sec_buf, &pls->init_sec_buf_size, sec_size);
}


int check_url(DASHContext *dash_ctx, AVIOContext **pb, const char *url) {
    const char *proto_name = NULL;
    int ret = 0;

    if (av_strstart(url, "crypto", NULL)) {
        if (url[6] == '+' || url[6] == ':')
            proto_name = avio_find_protocol_name(url + 7);
    }

    if (!proto_name)
        proto_name = avio_find_protocol_name(url);

    if (!proto_name)
        return AVERROR_INVALIDDATA;

    // only http(s) & file are allowed
    if (av_strstart(proto_name, "file", NULL)) {
        if (strcmp(dash_ctx->allowed_extensions, "ALL") && !av_match_ext(url, dash_ctx->allowed_extensions)) {
            av_log(dash_ctx, AV_LOG_ERROR,
                   "Filename extension of \'%s\' is not a common multimedia extension, blocked for security reasons.\n"
                   "If you wish to override this adjust allowed_extensions, you can set it to \'ALL\' to allow all\n",
                   url);
            return AVERROR_INVALIDDATA;
        }
    } else if (av_strstart(proto_name, "http", NULL)) {
        ;
    } else if (av_strstart(proto_name, "async", NULL)) {
        ;
    } else
        return AVERROR_INVALIDDATA;

    if (!strncmp(proto_name, url, strlen(proto_name)) && url[strlen(proto_name)] == ':')
        ;
    else if (av_strstart(url, "crypto", NULL) && !strncmp(proto_name, url + 7, strlen(proto_name)) && url[7 + strlen(proto_name)] == ':')
        ;
    else if (strcmp(proto_name, "file") || !strncmp(url, "file,", 5))
        return AVERROR_INVALIDDATA;

    av_freep(pb);
    return ret;
}

static pthread_mutex_t g_xml_mutex = PTHREAD_MUTEX_INITIALIZER;
int parse_dash_manifest(DASHContext *dash_ctx, const char *buffer, int buffer_size, const char *url)
{
    int ret = 0;
    xmlDoc *doc = NULL;
    xmlNodePtr root_element = NULL;
    xmlNodePtr node = NULL;
    xmlNodePtr period_node = NULL;
    xmlNodePtr tmp_node = NULL;
    xmlNodePtr mpd_baseurl_node = NULL;
    xmlNodePtr period_baseurl_node = NULL;
    xmlNodePtr period_segmenttemplate_node = NULL;
    xmlNodePtr period_segmentlist_node = NULL;
    xmlNodePtr adaptionset_node = NULL;
    xmlAttrPtr attr = NULL;
    char *val  = NULL;
    uint32_t period_duration_sec = 0;
    uint32_t period_start_sec = 0;

    pthread_mutex_lock(&g_xml_mutex);
    LIBXML_TEST_VERSION
    doc = xmlReadMemory(buffer, buffer_size, url, NULL, 0);
    root_element = xmlDocGetRootElement(doc);
    node = root_element;

    if (!node) {
        ret = AVERROR_INVALIDDATA;
        av_log(dash_ctx, AV_LOG_ERROR, "Unable to parse '%s' - missing root node\n", url);
        goto cleanup;
    }

    if (node->type != XML_ELEMENT_NODE ||
        av_strcasecmp((const char*)node->name, (const char *)"MPD")) {
        ret = AVERROR_INVALIDDATA;
        av_log(dash_ctx, AV_LOG_ERROR, "Unable to parse '%s' - wrong root node name[%s] type[%d]\n", url, node->name, (int)node->type);
        goto cleanup;
    }

    val = (char *)xmlGetProp(node, (const xmlChar*)"type");
    if (!val) {
        av_log(dash_ctx, AV_LOG_ERROR, "Unable to parse '%s' - missing type attrib\n", url);
        ret = AVERROR_INVALIDDATA;
        goto cleanup;
    }
    if (!av_strcasecmp(val, (const char *)"dynamic"))
        dash_ctx->is_live = 1;
    else if(!av_strcasecmp(val, (const char *)"static")){
        if(dash_ctx->is_live && !dash_ctx->is_live_ended){
            av_log(dash_ctx, AV_LOG_INFO, "live video is end, %s \n", url);
            dash_ctx->is_live_ended = 1;
        }
    }
    xmlFree(val);

    attr = node->properties;
    while (attr) {
        val = (char*)xmlGetProp(node, attr->name);

        if (!av_strcasecmp((const char *)attr->name, (const char *)"availabilityStartTime")) {
            dash_ctx->availability_start_time = get_time_in_sec_with_datetime((const char *)val);
        } else if (!av_strcasecmp((const char *)attr->name, (const char *)"publishTime")) {
            dash_ctx->publish_time = get_time_in_sec_with_datetime((const char *)val);
        } else if (!av_strcasecmp((const char *)attr->name, (const char *)"minimumUpdatePeriod")) {
            dash_ctx->minimum_update_period = get_time_in_sec_with_duration((const char *)val);
        } else if (!av_strcasecmp((const char *)attr->name, (const char *)"timeShiftBufferDepth")) {
            dash_ctx->time_shift_buffer_depth = get_time_in_sec_with_duration((const char *)val);
        } else if (!av_strcasecmp((const char *)attr->name, (const char *)"minBufferTime")) {
            dash_ctx->min_buffer_time = get_time_in_sec_with_duration((const char *)val);
        } else if (!av_strcasecmp((const char *)attr->name, (const char *)"suggestedPresentationDelay")) {
            dash_ctx->suggested_presentation_delay = get_time_in_sec_with_duration((const char *)val);
        } else if (!av_strcasecmp((const char *)attr->name, (const char *)"mediaPresentationDuration")) {
            dash_ctx->media_presentation_duration = get_time_in_sec_with_duration((const char *)val);
        }
        attr = attr->next;
        xmlFree(val);
    }

    tmp_node = find_child_node_by_name(node, "BaseURL");
    if (tmp_node) {
        mpd_baseurl_node = xmlCopyNode(tmp_node,1);
    } else {
        mpd_baseurl_node = xmlNewNode(NULL, (const xmlChar*)"BaseURL");
    }

    // at now we can handle only one period, with the longest duration
    node = xmlFirstElementChild(node);
    while (node) {
        if (!av_strcasecmp((const char *)node->name, (const char *)"Period")) {
            period_duration_sec = 0;
            period_start_sec = 0;
            attr = node->properties;
            while (attr) {
                val = (char*)xmlGetProp(node, attr->name);
                if (!av_strcasecmp((const char *)attr->name, (const char *)"duration")) {
                    period_duration_sec = get_time_in_sec_with_duration((const char *)val);
                } else if (!av_strcasecmp((const char *)attr->name, (const char *)"start")) {
                    period_start_sec = get_time_in_sec_with_duration((const char *)val);
                }
                attr = attr->next;
                xmlFree(val);
            }
            if ((period_duration_sec) >= (dash_ctx->period_duration)) {
                period_node = node;
                dash_ctx->period_duration = period_duration_sec;
                dash_ctx->period_start = period_start_sec;
                if (dash_ctx->period_start > 0)
                    dash_ctx->media_presentation_duration = dash_ctx->period_duration;
            }
        }
        node = xmlNextElementSibling(node);
    }
    if (!period_node) {
        av_log(dash_ctx, AV_LOG_ERROR, "Unable to parse '%s' - missing Period node\n", url);
        ret = AVERROR_INVALIDDATA;
        goto cleanup;
    }

    adaptionset_node = xmlFirstElementChild(period_node);
    while (adaptionset_node) {
        if (!av_strcasecmp((const char *)adaptionset_node->name, (const char *)"BaseURL")) {
            period_baseurl_node = adaptionset_node;
        } else if (!av_strcasecmp((const char *)adaptionset_node->name, (const char *)"SegmentTemplate")) {
            period_segmenttemplate_node = adaptionset_node;
        } else if (!av_strcasecmp((const char *)adaptionset_node->name, (const char *)"SegmentList")) {
            period_segmentlist_node = adaptionset_node;
        } else if (!av_strcasecmp((const char *)adaptionset_node->name, (const char *)"AdaptationSet")) {
            parse_manifest_adaptationset(dash_ctx, url, adaptionset_node, mpd_baseurl_node,
                                         period_baseurl_node, period_segmenttemplate_node, period_segmentlist_node);
        }
        adaptionset_node = xmlNextElementSibling(adaptionset_node);
    }
    cleanup:
    /*free the document */
    xmlFreeDoc(doc);
    xmlCleanupParser();
    xmlFreeNode(mpd_baseurl_node);
    pthread_mutex_unlock(&g_xml_mutex);

    return ret;
}


void move_timelines(struct representation *rep_src, struct representation *rep_dest, DASHContext *c) {
    if (rep_dest && rep_src ) {
        pthread_mutex_lock(&rep_dest->async_update_lock);
        free_timelines_list(rep_dest);
        rep_dest->timelines    = rep_src->timelines;
        rep_dest->n_timelines  = rep_src->n_timelines;
        rep_dest->first_seq_no = rep_src->first_seq_no;
        pthread_mutex_unlock(&rep_dest->async_update_lock);
        rep_dest->last_seq_no = calc_max_seg_no(rep_dest, c);
        rep_src->timelines = NULL;
        rep_src->n_timelines = 0;
        // only update cur_seq_no when it's out of mpd's range due to too slow.
        if (rep_dest->cur_seq_no < rep_src->cur_seq_no + rep_src->first_seq_no) {
            rep_dest->cur_seq_no = rep_src->cur_seq_no + rep_src->first_seq_no;
        }
    }
}

void move_segments(struct representation *rep_src, struct representation *rep_dest, DASHContext *c) {
    if (rep_dest && rep_src ) {
        pthread_mutex_lock(&rep_dest->async_update_lock);
        free_fragment_list(rep_dest);
        if (rep_src->start_number > (rep_dest->start_number + rep_dest->n_fragments))
            rep_dest->cur_seq_no = 0;
        else
            rep_dest->cur_seq_no += rep_src->start_number - rep_dest->start_number;
        rep_dest->fragments    = rep_src->fragments;
        rep_dest->n_fragments  = rep_src->n_fragments;
        rep_dest->parent  = rep_src->parent;
        pthread_mutex_unlock(&rep_dest->async_update_lock);
        rep_dest->last_seq_no = calc_max_seg_no(rep_dest, c);
        rep_src->fragments = NULL;
        rep_src->n_fragments = 0;
    }
}

int save_avio_options(AVFormatContext *s, DASHContext *c) {
    const char *opts[] = { "headers", "user_agent", "cookies", "reconnect",
                           "reconnect_count", "reconnect_delay_max", "timeout", "aptr", NULL }, **opt = opts;
    uint8_t *buf = NULL;
    int ret = 0;

    while (*opt) {
        if (av_opt_get(s->pb, *opt, AV_OPT_SEARCH_CHILDREN, &buf) >= 0) {
            if (buf[0] != '\0') {
                ret = av_dict_set(&c->avio_opts, *opt, (const char*)buf, AV_DICT_DONT_STRDUP_VAL);
                if (ret < 0) {
                    av_freep(&buf);
                    return ret;
                }
            } else {
                av_freep(&buf);
            }
        }
        opt++;
    }

    return ret;
}

int nested_io_open(AVFormatContext *s, AVIOContext **pb, const char *url,
                          int flags, AVDictionary **opts) {
    av_log(s, AV_LOG_ERROR,
           "A DASH playlist item '%s' referred to an external file '%s'. "
           "Opening this file was forbidden for security reasons\n",
           s->url, url);
    return AVERROR(EPERM);
}

void close_demux_for_component(struct representation *pls) {
    /* note: the internal buffer could have changed */
    av_freep(&pls->pb.buffer);
    memset(&pls->pb, 0x00, sizeof(AVIOContext));
    pls->ctx->pb = NULL;
    avformat_close_input(&pls->ctx);
    pls->ctx = NULL;
}

int64_t seek_data(void *opaque, int64_t offset, int whence) {
    struct representation *v = opaque;

    if (whence == AVSEEK_SIZE) {
        return avio_size(v->input);
    }

    if ((v->n_fragments && !v->init_sec_data_len) || v->is_segmentbase) {
        return avio_seek(v->input, offset, whence);
    }

    if (!v->n_fragments && offset > 0) {
        return avio_seek(v->input, offset - v->init_sec_data_len, whence);
    }

    return AVERROR(ENOSYS);
}

extern AVInputFormat ff_mov_demuxer;
#define INITIAL_BUFFER_SIZE_VIDEO 8192
#define INITIAL_BUFFER_SIZE_AUDIO 2048
#define AVFMT_FLAG_OUTSIDE_PB    0x0400

int reopen_demux_for_representation(AVFormatContext *s, DASHContext *dash_ctx, struct representation *pls) {
    AVInputFormat *in_fmt = NULL;
    AVDictionary  *in_fmt_opts = NULL;
    int ret = 0, i;
    int buffer_size = (pls->type == AVMEDIA_TYPE_AUDIO) ? INITIAL_BUFFER_SIZE_AUDIO : INITIAL_BUFFER_SIZE_VIDEO;

    pls->ctx->flags |= AVFMT_FLAG_CUSTOM_IO;
    pls->ctx->fps_probe_size = 3;
    in_fmt = &ff_mov_demuxer;
    pls->ctx->io_open  = nested_io_open;

    // provide additional information from mpd if available
    if (dash_ctx->decryption_key) {
        av_dict_set(&in_fmt_opts,"decryption_key", dash_ctx->decryption_key, 0);
    }
#if CONFIG_DRM
    if (dash_ctx->drm_ctx) {
        av_dict_set(&in_fmt_opts, "enable_drm", "true", 0);
        av_dict_set_int(&in_fmt_opts, "drm_downgrade", dash_ctx->drm_downgrade, 0);
        av_dict_set_int(&in_fmt_opts, "drm_aptr", (int64_t)(intptr_t) dash_ctx->drm_ctx, 0);
    }
#endif
    // av_dict_set_int(&in_fmt_opts, "cbptr", dash_ctx->cbptr, 0);
    ret = avformat_open_input(&pls->ctx, "", in_fmt, &in_fmt_opts); //pls->init_section->url
    av_dict_free(&in_fmt_opts);
    if (ret < 0) {
        if (pls->ctx) {
            avformat_close_input(&pls->ctx);
            pls->ctx = NULL;
        }
        goto fail;
    }
    if (pls->n_fragments || (!dash_ctx->skip_find_audio_stream_info && pls->type == AVMEDIA_TYPE_AUDIO && pls->down_segment_count == 1)) {
        for (i = 0; i < pls->ctx->nb_streams; i++) {
            pls->ctx->streams[i]->r_frame_rate = pls->framerate.den ? pls->framerate : pls->ctx->streams[i]->avg_frame_rate;
        }
        ret = avformat_find_stream_info(pls->ctx, NULL);
        if (ret < 0) {
            if (pls->ctx) {
                avformat_close_input(&pls->ctx);
                pls->ctx = NULL;
            }
            goto fail;
        }
    }
    pls->pb.seekable = dash_ctx->is_live ? 0 : 1;

    fail:
    av_log(s, AV_LOG_INFO, "reopen_demux_for_component type=%d, buffer_size=%d, ret=0x%x\n", pls->type, buffer_size, ret);
    return ret;
}

int read_from_url(struct representation *pls, struct fragment *seg,
                         uint8_t *buf, int buf_size, enum ReadFromURLMode mode) {
    int ret;

    /* limit read if the fragment was only a part of a file */
    if (seg->size >= 0)
        buf_size = FFMIN(buf_size, pls->cur_seg_size - pls->cur_seg_offset);

    if (mode == READ_COMPLETE) {
        ret = avio_read(pls->input, buf, buf_size);
        if (ret < buf_size) {
            av_log(pls->parent, AV_LOG_WARNING, "Could not read complete fragment.\n");
        }
    } else {
        ret = avio_read(pls->input, buf, buf_size);
    }
    if (ret > 0)
        pls->cur_seg_offset += ret;

    return ret;
}

int64_t find_nearest_fragment(struct representation *pls, int64_t pos_msec) {
    int i = 0;
    int j = 0;
    int64_t duration = 0;

    pthread_mutex_lock(&pls->async_update_lock);
    if (pls->n_timelines > 0 && pls->fragment_timescale > 0) {
        int64_t num = pls->first_seq_no;
        av_log(pls->parent, AV_LOG_VERBOSE, "dash SegmentTimeline start n_timelines[%d] "
                                            "last_seq_no[%"PRId64"], playlist %d.\n",
               (int)pls->n_timelines, (int64_t)pls->last_seq_no, (int)pls->rep_idx);
        for (i = 0; i < pls->n_timelines; i++) {
            if (pls->timelines[i]->starttime > 0) {
                duration = pls->timelines[i]->starttime;
            }
            duration += pls->timelines[i]->duration;
            if (pos_msec < ((duration * 1000) /  pls->fragment_timescale)) {
                goto set_seq_num;
            }
            for (j = 0; j < pls->timelines[i]->repeat; j++) {
                duration += pls->timelines[i]->duration;
                num++;
                if (pos_msec < ((duration * 1000) /  pls->fragment_timescale)) {
                    goto set_seq_num;
                }
            }
            num++;
        }

        set_seq_num:
        pthread_mutex_unlock(&pls->async_update_lock);
        return num > pls->last_seq_no ? pls->last_seq_no : num;
    } else if (pls->fragment_duration > 0) {
        pthread_mutex_unlock(&pls->async_update_lock);
        if (pos_msec > 0) {
            return pls->first_seq_no + av_rescale_rnd(pos_msec, pls->fragment_timescale, pls->fragment_duration * 1000, AV_ROUND_UP) - 1;
        }
        return pls->first_seq_no;
    } else {
        pthread_mutex_unlock(&pls->async_update_lock);
        av_log(pls->parent, AV_LOG_ERROR, "dash missing timeline or fragment_duration\n");
        return pls->first_seq_no;
    }
}

int64_t calc_cur_seg_no(DASHContext *dash_ctx, struct representation *pls) {
    int64_t num = 0;
    int64_t start_time_offset = 0;

    if (dash_ctx->is_live) {
        if (pls->n_fragments) {
            num = pls->first_seq_no;
        } else if (pls->n_timelines) {
            start_time_offset = get_segment_start_time_based_on_timeline(pls, 0xFFFFFFFF) - dash_ctx->low_delay_time_offset * pls->fragment_timescale; // 60 seconds before end
            num = calc_next_seg_no_from_timelines(pls, start_time_offset - 1);
            av_log(dash_ctx, AV_LOG_INFO, "calc_cur_seg_no num[%"PRId64"] first_seq_no[%"PRId64"] last_seq_no[%"PRId64"] offset '%d'\n",
                   num, pls->first_seq_no, pls->last_seq_no, dash_ctx->live_start_segment_offset);
            if (num == -1)
                num = pls->last_seq_no;
            else
                num += pls->first_seq_no;
        } else if (pls->fragment_duration){
            if (pls->presentation_timeoffset) {
                num = pls->presentation_timeoffset * pls->fragment_timescale / pls->fragment_duration;
            } else if (dash_ctx->publish_time > 0 && !dash_ctx->availability_start_time) {
                num = pls->first_seq_no + (((dash_ctx->publish_time - dash_ctx->availability_start_time) - dash_ctx->suggested_presentation_delay) * pls->fragment_timescale) / pls->fragment_duration;
            } else {
                num = pls->first_seq_no + (((get_time_in_sec_default() - dash_ctx->availability_start_time) - dash_ctx->suggested_presentation_delay) * pls->fragment_timescale) / pls->fragment_duration;
            }
        }
    } else {
        num = find_nearest_fragment(pls, dash_ctx->start_time);
        if (pls->cur_seq_no != 0) {
            return pls->cur_seq_no;
        }
    }
    return num;
}

// See ISO/IEC 23009-1:2014 5.3.9.4.4
typedef enum {
    DASH_TMPL_ID_UNDEFINED = -1,
    DASH_TMPL_ID_ESCAPE,
    DASH_TMPL_ID_REP_ID,
    DASH_TMPL_ID_NUMBER,
    DASH_TMPL_ID_BANDWIDTH,
    DASH_TMPL_ID_TIME,
} DASHTmplId;

static DASHTmplId dash_read_tmpl_id(const char *identifier, char *format_tag,
                                    size_t format_tag_size, const char **ptr) {
    const char *next_ptr;
    DASHTmplId id_type = DASH_TMPL_ID_UNDEFINED;

    if (av_strstart(identifier, "$$", &next_ptr)) {
        id_type = DASH_TMPL_ID_ESCAPE;
        *ptr = next_ptr;
    } else if (av_strstart(identifier, "$RepresentationID$", &next_ptr)) {
        id_type = DASH_TMPL_ID_REP_ID;
        // default to basic format, as $RepresentationID$ identifiers
        // are not allowed to have custom format-tags.
        av_strlcpy(format_tag, "%d", format_tag_size);
        *ptr = next_ptr;
    } else { // the following identifiers may have an explicit format_tag
        if (av_strstart(identifier, "$Number", &next_ptr))
            id_type = DASH_TMPL_ID_NUMBER;
        else if (av_strstart(identifier, "$Bandwidth", &next_ptr))
            id_type = DASH_TMPL_ID_BANDWIDTH;
        else if (av_strstart(identifier, "$Time", &next_ptr))
            id_type = DASH_TMPL_ID_TIME;
        else
            id_type = DASH_TMPL_ID_UNDEFINED;

        // next parse the dash format-tag and generate a c-string format tag
        // (next_ptr now points at the first '%' at the beginning of the format-tag)
        if (id_type != DASH_TMPL_ID_UNDEFINED) {
            const char *number_format = (id_type == DASH_TMPL_ID_TIME) ? PRId64 : "d";
            if (next_ptr[0] == '$') { // no dash format-tag
                snprintf(format_tag, format_tag_size, "%%%s", number_format);
                *ptr = &next_ptr[1];
            } else {
                const char *width_ptr;
                // only tolerate single-digit width-field (i.e. up to 9-digit width)
                if (av_strstart(next_ptr, "%0", &width_ptr) &&
                    av_isdigit(width_ptr[0]) &&
                    av_strstart(&width_ptr[1], "d$", &next_ptr)) {
                    // yes, we're using a format tag to build format_tag.
                    snprintf(format_tag, format_tag_size, "%s%c%s", "%0", width_ptr[0], number_format);
                    *ptr = next_ptr;
                } else {
                    av_log(NULL, AV_LOG_WARNING, "Failed to parse format-tag beginning with %s. Expected either a "
                                                 "closing '$' character or a format-string like '%%0[width]d', "
                                                 "where width must be a single digit\n", next_ptr);
                    id_type = DASH_TMPL_ID_UNDEFINED;
                }
            }
        }
    }
    return id_type;
}

void ff_cmaf_fill_tmpl_params(char *dst, size_t buffer_size,
                              const char *template, int rep_id,
                              int number, int bit_rate,
                              int64_t time) {
    int dst_pos = 0;
    const char *t_cur = template;
    while (dst_pos < buffer_size - 1 && *t_cur) {
        char format_tag[7]; // May be "%d", "%0Xd", or "%0Xlld" (for $Time$), where X is in [0-9]
        int n = 0;
        DASHTmplId id_type;
        const char *t_next = strchr(t_cur, '$'); // copy over everything up to the first '$' character
        if (t_next) {
            int num_copy_bytes = FFMIN(t_next - t_cur, buffer_size - dst_pos - 1);
            av_strlcpy(&dst[dst_pos], t_cur, num_copy_bytes + 1);
            // advance
            dst_pos += num_copy_bytes;
            t_cur = t_next;
        } else { // no more DASH identifiers to substitute - just copy the rest over and break
            av_strlcpy(&dst[dst_pos], t_cur, buffer_size - dst_pos);
            break;
        }

        if (dst_pos >= buffer_size - 1 || !*t_cur)
            break;

        // t_cur is now pointing to a '$' character
        id_type = dash_read_tmpl_id(t_cur, format_tag, sizeof(format_tag), &t_next);
        switch (id_type) {
            case DASH_TMPL_ID_ESCAPE:
                av_strlcpy(&dst[dst_pos], "$", 2);
                n = 1;
                break;
            case DASH_TMPL_ID_REP_ID:
                n = snprintf(&dst[dst_pos], buffer_size - dst_pos, format_tag, rep_id);
                break;
            case DASH_TMPL_ID_NUMBER:
                n = snprintf(&dst[dst_pos], buffer_size - dst_pos, format_tag, number);
                break;
            case DASH_TMPL_ID_BANDWIDTH:
                n = snprintf(&dst[dst_pos], buffer_size - dst_pos, format_tag, bit_rate);
                break;
            case DASH_TMPL_ID_TIME:
                n = snprintf(&dst[dst_pos], buffer_size - dst_pos, format_tag, time);
                break;
            case DASH_TMPL_ID_UNDEFINED:
                // copy over one byte and advance
                av_strlcpy(&dst[dst_pos], t_cur, 2);
                n = 1;
                t_next = &t_cur[1];
                break;
        }
        // t_next points just past the processed identifier
        // n is the number of bytes that were attempted to be written to dst
        // (may have failed to write all because buffer_size).

        // advance
        dst_pos += FFMIN(n, buffer_size - dst_pos - 1);
        t_cur = t_next;
    }
}

struct fragment *getFragment(struct representation *pls, struct fragment *seg, const DASHContext *dash_ctx) {
    if (seg) {
        char *tmpfilename = av_mallocz(dash_ctx->max_url_size);
        if (!tmpfilename || !pls->url_template) {
            av_free(seg);
            av_freep(&tmpfilename);
            return NULL;
        }
        ff_cmaf_fill_tmpl_params(tmpfilename, dash_ctx->max_url_size, pls->url_template, 0, pls->cur_seq_no, 0,
                                 get_segment_start_time_based_on_timeline(pls, pls->cur_seq_no));
        seg->url = av_strireplace(pls->url_template, pls->url_template, tmpfilename);
        if (!seg->url) {
            av_log(pls->parent, AV_LOG_WARNING, "Unable to resolve template url '%s', try to use origin template\n", pls->url_template);
            seg->url = av_strdup(pls->url_template);
            if (!seg->url) {
                av_log(pls->parent, AV_LOG_ERROR, "Cannot resolve template url '%s'\n", pls->url_template);
                av_free(seg);
                av_free(tmpfilename);
                return NULL;
            }
        }
        av_free(tmpfilename);
        seg->size = -1;
    }

    return seg;
}

int is_common_init_section_exist(struct representation **pls, int n_pls)
{
    struct fragment *first_init_section = pls[0]->init_section;
    char *url =NULL;
    int64_t url_offset = -1;
    int64_t size = -1;
    int i = 0;

    if (first_init_section == NULL || n_pls == 0)
        return 0;

    url = first_init_section->url;
    url_offset = first_init_section->url_offset;
    size = pls[0]->init_section->size;
    for (i=0;i<n_pls;i++) {
        if (av_strcasecmp(pls[i]->init_section->url,url) || pls[i]->init_section->url_offset != url_offset || pls[i]->init_section->size != size) {
            return 0;
        }
    }
    return 1;
}


int check_init_section(uint8_t *sec_buf) {
    if (!sec_buf) {
        av_log(NULL, AV_LOG_ERROR, "check init section failed, sec_buf is null\n");
        return AVERROR_INVALIDDATA;
    }
    if (!av_stristr((const char*)sec_buf, "<MPD")) {
        return 0;
    }
    if (av_stristr((const char*)sec_buf, "dash:profile:isoff-on-demand:2011") ||
        av_stristr((const char*)sec_buf, "dash:profile:isoff-live:2011") ||
        av_stristr((const char*)sec_buf, "dash:profile:isoff-live:2012") ||
        av_stristr((const char*)sec_buf, "dash:profile:isoff-main:2011") ||
        av_stristr((const char*)sec_buf, "dash:profile")) {
        av_log(NULL, AV_LOG_ERROR, "check init section failed\n");
        return AVERROR_INVALIDDATA;
    }
    return 0;
}
