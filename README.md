# docker sysconf hook

## About

Inspired from [container_cpu_detection](https://github.com/agile6v/container_cpu_detection)
hook sysconf(_SC_AVPHYS_PAGES) && sysconf(_SC_AVPHYS_PAGES)


## Usage
* make

    docker run -ti --rm \
    --cpuset-cpus 0,1 --cpu-quota 200000 \
    -v `pwd`/detection.so:/usr/lib/memory_hook.so \
    -e LD_PRELOAD=/usr/lib/memory_hook.so \
    centos:7 


