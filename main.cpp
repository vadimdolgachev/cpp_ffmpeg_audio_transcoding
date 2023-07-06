extern "C" {
#include <libavutil/frame.h>
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libswresample/swresample.h>
#include <libavutil/audio_fifo.h>
}

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>

std::string avErr2Str(const int error) {
    std::string errorStr(AV_ERROR_MAX_STRING_SIZE, '\0');
    av_make_error_string(errorStr.data(), AV_ERROR_MAX_STRING_SIZE, error);
    return errorStr;
}

template<typename T, auto DeleterFn>
using UniquePtrDeleter = std::unique_ptr<T, decltype(DeleterFn)>;

using AVPacketPtr = UniquePtrDeleter<AVPacket, [](auto *ptr) { av_packet_free(&ptr); }>;
using AVCodecContextPtr = UniquePtrDeleter<AVCodecContext, [](auto *ptr) { avcodec_free_context(&ptr); }>;
using SwrContextPtr = UniquePtrDeleter<SwrContext, [](auto *ptr) { swr_free(&ptr); }>;
using AVFramePtr = UniquePtrDeleter<AVFrame, [](auto *ptr) { av_frame_free(&ptr); }>;
using AVAudioFifoPtr = UniquePtrDeleter<AVAudioFifo, [](auto *ptr) { av_audio_fifo_free(ptr); }>;
using AVFormatContextPtr = UniquePtrDeleter<AVFormatContext, [](auto *ptr) { avformat_free_context(ptr); }>;
using AVAudioSamplesPtr = UniquePtrDeleter<uint8_t *, [](auto *ptr) {
    av_freep(&ptr[0]);
    av_freep(&ptr);
}>;

template<typename T>
inline T *checkPtr(T *const ptr, const std::string &msg) {
    if (ptr == nullptr) {
        throw std::runtime_error(msg);
    }
    return ptr;
}

template<typename... Arg>
concept IntVarArgs = (std::is_same<Arg, int>::value && ...);

inline int checkAVRetLess(const int returnValue, int lessThan, const std::string &msg, IntVarArgs auto &&... except) {
    if (returnValue < lessThan && !((returnValue == except) || ...)) {
        throw std::runtime_error(std::string(msg).append("\n").append(avErr2Str(returnValue)));
    }
    return returnValue;
}

inline int checkAVRet(const int returnValue, const std::string &msg, auto &&... except) {
    return checkAVRetLess(returnValue, 0, msg, std::forward<decltype(except)>(except)...);
}

AVPacketPtr createAVPacket() {
    return AVPacketPtr(checkPtr(av_packet_alloc(), "Error allocation av packet"));
}

AVAudioSamplesPtr createAudioSamples(const int frameSize,
                                     const int channels,
                                     const AVSampleFormat sampleFormat) {
    uint8_t **rawData = nullptr;
    checkAVRet(av_samples_alloc_array_and_samples(&rawData,
                                                  nullptr,
                                                  channels,
                                                  frameSize,
                                                  sampleFormat,
                                                  0),
               "Could not allocate converted input samples");
    return AVAudioSamplesPtr(rawData);
}

void decodeConvertAndWriteToFifo(const AVAudioFifoPtr &fifo,
                                 const AVCodecContextPtr &inputCodexCxt,
                                 const AVCodecContextPtr &outputCodecCxt,
                                 const SwrContextPtr &resampleCxt,
                                 const AVPacketPtr &pkt,
                                 const AVFramePtr &frame) {
    checkAVRet(avcodec_send_packet(inputCodexCxt.get(), pkt.get()),
               "Error submitting the packet to the decoder");
    const int frameSize = inputCodexCxt->frame_size;
    auto audioBuffer = createAudioSamples(frameSize, outputCodecCxt->channels, outputCodecCxt->sample_fmt);
    for (;;) {
        if (const auto ret = checkAVRet(avcodec_receive_frame(inputCodexCxt.get(), frame.get()),
                                        "Error during decoding",
                                        AVERROR(EAGAIN), AVERROR_EOF);
                ret == AVERROR(EAGAIN) || ret == AVERROR_EOF) {
            break;
        }
        checkAVRet(swr_convert(resampleCxt.get(),
                               audioBuffer.get(),
                               frameSize,
                               const_cast<const uint8_t **>(frame->extended_data),
                               frameSize),
                   "Could not convert input samples");

        checkAVRet(av_audio_fifo_write(fifo.get(),
                                           reinterpret_cast<void **>(audioBuffer.get()),
                                           frameSize),
                       "Could not write data to FIFO");
    }
}

AVFramePtr createAVFrame() {
    return AVFramePtr(checkPtr(av_frame_alloc(), "Error allocation av frame"));
}

AVFramePtr ensureFrame(const AVCodecContextPtr &codecCxt) {
    auto frame = createAVFrame();
    frame->nb_samples = codecCxt->frame_size;
    frame->channels = codecCxt->channels;
    frame->channel_layout = codecCxt->channel_layout;
    frame->format = codecCxt->sample_fmt;
    frame->sample_rate = codecCxt->sample_rate;

    checkAVRet(av_frame_get_buffer(frame.get(), 0),
               "Could not allocate output frame samples");
    return frame;
}

AVCodecContextPtr createInputCodecContext(const AVFormatContextPtr &formatContext) {
    const auto *codec = checkPtr(avcodec_find_decoder(formatContext->streams[0]->codecpar->codec_id),
                                 "Decoder is not found");
    auto codecCxt = AVCodecContextPtr(checkPtr(avcodec_alloc_context3(codec),
                                               "Error allocation input codec context"));
    checkAVRet(avformat_find_stream_info(formatContext.get(), nullptr),
               "Could not find audio stream");
    checkAVRet(avcodec_parameters_to_context(codecCxt.get(), formatContext->streams[0]->codecpar),
               "Could not fill codec context from format");
    checkAVRet(avcodec_open2(codecCxt.get(), codec, nullptr), "Error open codec");
    return codecCxt;
}

AVFormatContextPtr avformatOpenInput(const char *const inputUrl) {
    AVFormatContext *context = nullptr;
    checkAVRet(avformat_open_input(&context, inputUrl, nullptr, nullptr), "Error open input url");
    return AVFormatContextPtr(context);
}

AVFormatContextPtr createOutputFormatContext(const char *const outputFileName) {
    auto formatContext = AVFormatContextPtr(checkPtr(avformat_alloc_context(),
                                                     "Error allocation output format context"));
    checkAVRet(avio_open(&formatContext->pb, outputFileName, AVIO_FLAG_WRITE), "Could not open output file");

    formatContext->oformat = checkPtr(av_guess_format(nullptr, outputFileName, nullptr),
                                      "Could not find output file format");
    formatContext->url = checkPtr(av_strdup(outputFileName), "Could not allocate url.");
    return formatContext;
}

AVCodecContextPtr createOutputCodecContext(const AVCodecContextPtr &inputCodecCxt,
                                           const AVFormatContextPtr &outputFormatCxt) {
    auto *outputCodec = checkPtr(avcodec_find_encoder(AV_CODEC_ID_AC3),
                                 "Could not find AC3 encoder");
    auto outputCodecCxt = AVCodecContextPtr(checkPtr(avcodec_alloc_context3(outputCodec),
                                                     "Error allocation encoder context"));
    outputCodecCxt->channels = inputCodecCxt->channels;
    outputCodecCxt->channel_layout = av_get_default_channel_layout(inputCodecCxt->channels);
    outputCodecCxt->sample_rate = inputCodecCxt->sample_rate;
    outputCodecCxt->sample_fmt = outputCodec->sample_fmts[0];
    outputCodecCxt->bit_rate = inputCodecCxt->bit_rate;
    outputCodecCxt->strict_std_compliance = FF_COMPLIANCE_EXPERIMENTAL;

    if ((outputFormatCxt->oformat->flags & AVFMT_GLOBALHEADER) == AVFMT_GLOBALHEADER) {
        outputCodecCxt->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;
    }

    AVStream *stream = checkPtr(avformat_new_stream(outputFormatCxt.get(), nullptr),
                                "Could not create new stream");
    stream->time_base.den = inputCodecCxt->sample_rate;
    stream->time_base.num = 1;
    checkAVRet(avcodec_parameters_from_context(stream->codecpar, outputCodecCxt.get()),
               "Could not initialize stream parameters");
    checkAVRet(avformat_write_header(outputFormatCxt.get(), nullptr),
               "Could not write output file header");
    checkAVRet(avcodec_open2(outputCodecCxt.get(), outputCodec, nullptr),
               "Could not open output codec");
    return outputCodecCxt;
}

SwrContextPtr createSwrContext(const AVCodecContextPtr &inputCodecCxt,
                               const AVCodecContextPtr &outputCodecCxt) {
    auto resampleCxt = SwrContextPtr(checkPtr(swr_alloc_set_opts(nullptr,
                                                                 av_get_default_channel_layout(
                                                                         outputCodecCxt->channels),
                                                                 outputCodecCxt->sample_fmt,
                                                                 outputCodecCxt->sample_rate,
                                                                 av_get_default_channel_layout(inputCodecCxt->channels),
                                                                 inputCodecCxt->sample_fmt,
                                                                 inputCodecCxt->sample_rate,
                                                                 0, nullptr),
                                              "Could not allocate resample context"));
    checkAVRet(swr_init(resampleCxt.get()), "Could not open resample context");
    return resampleCxt;
}

AVAudioFifoPtr createFifo(const AVCodecContextPtr &outputCodecCxt) {
    return AVAudioFifoPtr(checkPtr(av_audio_fifo_alloc(outputCodecCxt->sample_fmt,
                                                       outputCodecCxt->channels,
                                                       1), "Error allocation av audio fifo"));
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return EXIT_FAILURE;
    }
    try {
        auto avFrame = createAVFrame();
        auto avPacket = createAVPacket();

        auto inputFormatCxt = avformatOpenInput(argv[1]);
        auto inputCodecCxt = createInputCodecContext(inputFormatCxt);

        auto outputFormatCxt = createOutputFormatContext(argv[2]);
        auto outputCodecCxt = createOutputCodecContext(inputCodecCxt, outputFormatCxt);

        auto resampleCxt = createSwrContext(inputCodecCxt, outputCodecCxt);

        auto encodeFrame = ensureFrame(outputCodecCxt);
        auto audioFifo = createFifo(outputCodecCxt);

        const int outputFrameSize = outputCodecCxt->frame_size;
        std::int64_t pts = 0;
        bool isFinished = false;
        while (!isFinished) {
            // decoding
            while (av_audio_fifo_size(audioFifo.get()) < outputFrameSize) {
                if (av_read_frame(inputFormatCxt.get(), avPacket.get()) < 0) {
                    std::cout << "av_read_frame: end of file\n";
                    isFinished = true;
                    break;
                }
                decodeConvertAndWriteToFifo(audioFifo, inputCodecCxt, outputCodecCxt, resampleCxt, avPacket, avFrame);
                av_packet_unref(avPacket.get());
            }

            // encoding
            int fifoSize = av_audio_fifo_size(audioFifo.get());
            while (fifoSize >= outputFrameSize) {
                const int frameSize = std::min(fifoSize, outputCodecCxt->frame_size);
                checkAVRet(av_audio_fifo_read(audioFifo.get(), reinterpret_cast<void **>(encodeFrame->data), frameSize),
                           "Could not read av frame from fifo");
                encodeFrame->pts = pts;
                pts += encodeFrame->nb_samples;
                checkAVRet(avcodec_send_frame(outputCodecCxt.get(), encodeFrame.get()),
                           "Could not send packet for encoding");
                checkAVRet(avcodec_receive_packet(outputCodecCxt.get(), avPacket.get()),
                           "Could not receive packet for encoding");
                checkAVRet(av_write_frame(outputFormatCxt.get(), avPacket.get()),
                           "Could not write av frame");
                av_packet_unref(avPacket.get());

                fifoSize = av_audio_fifo_size(audioFifo.get());
            }
        }
    } catch (const std::exception &e) {
        std::cerr << e.what() << "\n";
    }
    return 0;
}
