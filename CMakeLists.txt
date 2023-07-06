cmake_minimum_required(VERSION 3.26)
project(ffmpeg_audio_decode)

set(CMAKE_CXX_STANDARD 20)

find_library(AVCODEC_LIBRARY avcodec)
find_library(AVFORMAT_LIBRARY avformat)
find_library(AVUTIL_LIBRARY avutil)
find_library(SWRESAMPLE_LIBRARY swresample)

add_executable(ffmpeg_audio_decode main.cpp)
target_link_libraries(ffmpeg_audio_decode PRIVATE
        ${AVCODEC_LIBRARY}
        ${AVFORMAT_LIBRARY}
        ${AVUTIL_LIBRARY}
        ${SWRESAMPLE_LIBRARY})