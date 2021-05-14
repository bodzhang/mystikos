# stage 1 build
FROM alpine:3.12.3 AS cpprest-base-image

RUN apk add --no-cache curl build-base bash git boost-dev cmake zlib-dev openssl-dev ninja

RUN rm -rf /app;mkdir -p /app
	
WORKDIR /app
RUN git clone https://github.com/Microsoft/cpprestsdk.git casablanca
RUN cd casablanca;\
        mkdir -p build.debug; cd build.debug;\
        cmake -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCPPREST_EXCLUDE_WEBSOCKETS=ON  ..;\
        cd ..;\
        mkdir -p build.release; cd build.release;\
        cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DCPPREST_EXCLUDE_WEBSOCKETS=ON  ..;\
        cd ..;\
        ninja -C build.debug;\
        ninja -C build.release;
