FROM python:3.6-slim

RUN apt-get update && apt-get install -y \
    curl

RUN python3 -m pip install --upgrade pip

#tensorflow for python3.9
#RUN python3 -m pip install \
#    https://storage.googleapis.com/tensorflow/linux/cpu/tensorflow_cpu-2.5.0-cp39-cp39-manylinux2010_x86_64.whl \
#    pillow

#tensorflow for python3.6
RUN python3 -m pip install \
    https://storage.googleapis.com/tensorflow/linux/cpu/tensorflow_cpu-2.5.0-cp36-cp36m-manylinux2010_x86_64.whl \
    pillow

#RUN python3 -m pip install pillow

# Create a working directory
RUN mkdir /app
WORKDIR /app
ADD label_image.py /app
ADD mnist_convnet.py /app

# Get photo
RUN curl https://raw.githubusercontent.com/tensorflow/tensorflow/master/tensorflow/lite/examples/label_image/testdata/grace_hopper.bmp > /tmp/grace_hopper.bmp
# Get model
RUN curl https://storage.googleapis.com/download.tensorflow.org/models/mobilenet_v1_2018_02_22/mobilenet_v1_1.0_224.tgz | tar xzv -C /tmp
# Get labels
RUN curl https://storage.googleapis.com/download.tensorflow.org/models/mobilenet_v1_1.0_224_frozen.tgz  | tar xzv -C /tmp  mobilenet_v1_1.0_224/labels.txt

RUN mv /tmp/mobilenet_v1_1.0_224/labels.txt /tmp/

#numpy installed with python3-tflite-runtime is broken. Remove it to use pip-intalled version
#RUN rm -fr /usr/lib/python3/dist-packages/numpy

#ENV PYTHONPATH='/usr/lib/python3/dist-packages'
