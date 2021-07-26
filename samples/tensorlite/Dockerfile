FROM python:3.8

RUN apt-get update && apt-get install -y \
    build-essential \
    curl

RUN python3 -m pip install --upgrade pip

RUN pip3 install pillow

RUN python3 -m pip install --index-url https://google-coral.github.io/py-repo/ --extra-index-url=https://pypi.python.org/simple tflite-runtime

# Create a working directory
RUN mkdir /app
WORKDIR /app
ADD label_image.py /app

# Get photo
RUN curl https://raw.githubusercontent.com/tensorflow/tensorflow/master/tensorflow/lite/examples/label_image/testdata/grace_hopper.bmp > /tmp/grace_hopper.bmp
# Get model
RUN curl https://storage.googleapis.com/download.tensorflow.org/models/mobilenet_v1_2018_02_22/mobilenet_v1_1.0_224.tgz | tar xzv -C /tmp
# Get labels
RUN curl https://storage.googleapis.com/download.tensorflow.org/models/mobilenet_v1_1.0_224_frozen.tgz  | tar xzv -C /tmp  mobilenet_v1_1.0_224/labels.txt

RUN mv /tmp/mobilenet_v1_1.0_224/labels.txt /tmp/

CMD ["/bin/bash"]
# CMD ["/usr/bin/python3", "/app/mnist_convnet.py"]