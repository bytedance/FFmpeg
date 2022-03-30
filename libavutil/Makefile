include $(SUBDIR)../config.mak

NAME = avutil

HEADERS = adler32.h                                                     \
          aes.h                                                         \
          aes_ctr.h                                                     \
          attributes.h                                                  \
          audio_fifo.h                                                  \
          avassert.h                                                    \
          avstring.h                                                    \
          avutil.h                                                      \
          base64.h                                                      \
          blowfish.h                                                    \
          bprint.h                                                      \
          bswap.h                                                       \
          buffer.h                                                      \
          cast5.h                                                       \
          camellia.h                                                    \
          channel_layout.h                                              \
          common.h                                                      \
          cpu.h                                                         \
          crc.h                                                         \
          des.h                                                         \
          dict.h                                                        \
          display.h                                                     \
          dovi_meta.h                                                   \
          downmix_info.h                                                \
          encryption_info.h                                             \
          error.h                                                       \
          eval.h                                                        \
          fifo.h                                                        \
          file.h                                                        \
          frame.h                                                       \
          hash.h                                                        \
          hmac.h                                                        \
          hwcontext.h                                                   \
          hwcontext_cuda.h                                              \
          hwcontext_dxva2.h                                             \
          hwcontext_qsv.h                                               \
          hwcontext_vaapi.h                                             \
          hwcontext_vdpau.h                                             \
          hwcontext_videotoolbox.h                                      \
          imgutils.h                                                    \
          intfloat.h                                                    \
          intreadwrite.h                                                \
          lfg.h                                                         \
          log.h                                                         \
          macros.h                                                      \
          mathematics.h                                                 \
          mastering_display_metadata.h                                  \
          md5.h                                                         \
          mem.h                                                         \
          motion_vector.h                                               \
          murmur3.h                                                     \
          opt.h                                                         \
          parseutils.h                                                  \
          pixdesc.h                                                     \
          pixelutils.h                                                  \
          pixfmt.h                                                      \
          random_seed.h                                                 \
          rc4.h                                                         \
          rational.h                                                    \
          replaygain.h                                                  \
          ripemd.h                                                      \
          samplefmt.h                                                   \
          sha.h                                                         \
          sha512.h                                                      \
          spherical.h                                                   \
          stereo3d.h                                                    \
          threadmessage.h                                               \
          time.h                                                        \
          timecode.h                                                    \
          timestamp.h                                                   \
          tree.h                                                        \
          twofish.h                                                     \
          version.h                                                     \
          xtea.h                                                        \
          tea.h                                                         \
          thread.h                                                      \
          time_internal.h                                               \
          reverse.h                                                     \
          mdl_info_wrapper.h                                            \
          ttmapp.h                                                      \

HEADERS-$(CONFIG_LZO)                   += lzo.h

HEADERS-$(CONFIG_OPENCL)                += opencl.h

HEADERS-$(CONFIG_DRM)                   += drm.h

ARCH_HEADERS = bswap.h                                                  \
               intmath.h                                                \
               intreadwrite.h                                           \
               timer.h                                                  \

BUILT_HEADERS = avconfig.h                                              \
                ffversion.h

OBJS = avstring.o                                                       \
       bprint.o                                                         \
       buffer.o                                                         \
       channel_layout.o                                                 \
       cpu.o                                                            \
       dict.o                                                           \
       display.o                                                        \
       dovi_meta.o                                                      \
       error.o                                                          \
       eval.o                                                           \
       fifo.o                                                           \
       file_open.o                                                      \
       frame.o                                                          \
       imgutils.o                                                       \
       log.o                                                            \
       mathematics.o                                                    \
       mastering_display_metadata.o                                     \
       mem.o                                                            \
       opt.o                                                            \
       parseutils.o                                                     \
       pixdesc.o                                                        \
       random_seed.o                                                    \
       rational.o                                                       \
       reverse.o                                                        \
       samplefmt.o                                                      \
       spherical.o                                                      \
       stereo3d.o                                                       \
       time.o                                                           \
       timecode.o                                                       \
       utils.o                                                          \
       ttmapp.o                                                         \

OBJS-$(!CONFIG_LITE) += aes.o                          \
                        aes_ctr.o                      \
                        base64.o                       \
                        blowfish.o                     \
                        cast5.o                        \
                        camellia.o                     \
                        color_utils.o                  \
                        des.o                          \
                        downmix_info.o                 \
                        encryption_info.o              \
                        fixed_dsp.o                    \
                        hash.o                         \
                        hmac.o                         \
                        integer.o                      \
                        intmath.o                      \
                        lls.o                          \
                        murmur3.o                      \
                        rc4.o                          \
                        ripemd.o                       \
                        rc4.o                          \
                        ripemd.o                       \
                        sha.o                          \
                        sha512.o                       \
                        threadmessage.o                \
                        tree.o                         \
                        twofish.o                      \
                        xtea.o                         \
                        tea.o                          \
                        mdl_info_wrapper.o             \
                        audio_fifo.o                   \
                        lfg.o                          \
                        float_dsp.o                    \
                        xga_font_data.o                \
                        pixelutils.o                   \
                        file.o                         \
                        hwcontext.o                    \
                        adler32.o                      \
                        crc.o                          \
                        md5.o                          \

OBJS-$(CONFIG_FILTERS) += audio_fifo.o                   \
                          lfg.o                          \
                          float_dsp.o                    \
                          xga_font_data.o                \
                          pixelutils.o                   \
                          file.o                         \
                          hwcontext.o                    \
                          adler32.o                      \
                          crc.o                          \
                          md5.o                          \

OBJS-$(CONFIG_HTTPS_PROTOCOL) += base64.o

OBJS-$(CONFIG_DECODERS) += log2_tab.o

OBJS-$(!HAVE_ATOMICS_NATIVE)            += atomic.o                     \

OBJS-$(CONFIG_CUDA)                     += hwcontext_cuda.o
OBJS-$(CONFIG_DXVA2)                    += hwcontext_dxva2.o
OBJS-$(CONFIG_QSV)                   += hwcontext_qsv.o
OBJS-$(CONFIG_LZO)                      += lzo.o
OBJS-$(CONFIG_OPENCL)                   += opencl.o opencl_internal.o
OBJS-$(CONFIG_VAAPI)                    += hwcontext_vaapi.o
OBJS-$(CONFIG_VDPAU)                    += hwcontext_vdpau.o
OBJS-$(CONFIG_VIDEOTOOLBOX)             += hwcontext_videotoolbox.o
OBJS-$(CONFIG_DRM)                      += drm.o

OBJS += $(COMPAT_OBJS:%=../compat/%)

# Windows resource file
SLIBOBJS-$(HAVE_GNU_WINDRES)            += avutilres.o

SKIPHEADERS-$(HAVE_CUDA_H)             += hwcontext_cuda.h
SKIPHEADERS-$(CONFIG_CUDA)             += hwcontext_cuda_internal.h
SKIPHEADERS-$(CONFIG_DXVA2)            += hwcontext_dxva2.h
SKIPHEADERS-$(CONFIG_QSV)              += hwcontext_qsv.h
SKIPHEADERS-$(CONFIG_VAAPI)            += hwcontext_vaapi.h
SKIPHEADERS-$(CONFIG_VDPAU)            += hwcontext_vdpau.h
SKIPHEADERS-$(CONFIG_VIDEOTOOLBOX)     += hwcontext_videotoolbox.h
SKIPHEADERS-$(HAVE_ATOMICS_GCC)        += atomic_gcc.h
SKIPHEADERS-$(HAVE_ATOMICS_SUNCC)      += atomic_suncc.h
SKIPHEADERS-$(HAVE_ATOMICS_WIN32)      += atomic_win32.h
SKIPHEADERS-$(CONFIG_OPENCL)           += opencl.h

TESTPROGS = adler32                                                     \
            aes                                                         \
            aes_ctr                                                     \
            atomic                                                      \
            audio_fifo                                                  \
            avstring                                                    \
            base64                                                      \
            blowfish                                                    \
            bprint                                                      \
            cast5                                                       \
            camellia                                                    \
            color_utils                                                 \
            cpu                                                         \
            crc                                                         \
            des                                                         \
            dict                                                        \
            display                                                     \
            error                                                       \
            eval                                                        \
            file                                                        \
            fifo                                                        \
            float_dsp                                                   \
            hash                                                        \
            hmac                                                        \
            imgutils                                                    \
            lfg                                                         \
            lls                                                         \
            log                                                         \
            md5                                                         \
            murmur3                                                     \
            opt                                                         \
            pca                                                         \
            parseutils                                                  \
            pixdesc                                                     \
            pixelutils                                                  \
            random_seed                                                 \
            rational                                                    \
            ripemd                                                      \
            sha                                                         \
            sha512                                                      \
            softfloat                                                   \
            tree                                                        \
            twofish                                                     \
            utf8                                                        \
            xtea                                                        \
            tea                                                         \

TESTPROGS-$(HAVE_LZO1X_999_COMPRESS) += lzo
TESTPROGS-$(HAVE_THREADS) += cpu_init

TOOLS = crypto_bench ffhash ffeval ffescape

tools/crypto_bench$(EXESUF): ELIBS += $(if $(VERSUS),$(subst +, -l,+$(VERSUS)),)
tools/crypto_bench$(EXESUF): CFLAGS += -DUSE_EXT_LIBS=0$(if $(VERSUS),$(subst +,+USE_,+$(VERSUS)),)

$(SUBDIR)tests/lzo$(EXESUF): ELIBS = -llzo2
