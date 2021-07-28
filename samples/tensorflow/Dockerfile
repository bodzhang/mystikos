FROM python:3.9-slim

RUN python3 -m pip install --upgrade pip

RUN pip3 install https://storage.googleapis.com/tensorflow/linux/cpu/tensorflow_cpu-2.5.0-cp39-cp39-manylinux2010_x86_64.whl

# Create a working directory
RUN mkdir /app
WORKDIR /app
ADD mnist_convnet.py /app

CMD ["/bin/bash"]
# CMD ["/usr/bin/python3", "/app/mnist_convnet.py"]