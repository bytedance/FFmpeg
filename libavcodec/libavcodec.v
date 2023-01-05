LIBAVCODEC_MAJOR {
    global:
        av*;
        ff_combine_frame;
        #deprecated, remove after next bump
        audio_resample;
        audio_resample_close;
    local:
        *;
};
