# This Dockerfile is based on: 
# https://hub.docker.com/r/godatadriven/pyspark/dockerfile

# Selection of the (OS)Build
FROM openjdk:8-jre-slim

# Docker variable
ARG BUILD_DATE
ARG SPARK_VERSION=3.1.2

# Set labels (if you want to)
LABEL org.label-schema.name="Apache PySpark $SPARK_VERSION" \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.version=$SPARK_VERSION

# Set environment variables in Docker Container
ENV PATH="/opt/miniconda3/bin:${PATH}"
ENV PYSPARK_PYTHON="/opt/miniconda3/bin/python3"
ENV PYTHONUNBUFFERED=1

COPY . /app
WORKDIR /app

# Install the required Applications
# iputils-ping is for testing purposes
RUN apt-get update && \
    apt-get install -y curl bzip2 --no-install-recommends && \
    apt-get install -y iputils-ping && \
    curl -sLo /tmp/miniconda.sh https://repo.continuum.io/miniconda/Miniconda3-latest-Linux-x86_64.sh && \
    bash /tmp/miniconda.sh -b -f -p "/opt/miniconda3" && \
    rm /tmp/miniconda.sh && \
    conda config --set auto_update_conda true && \
    conda config --set channel_priority false && \
    conda update conda -y --force && \
    conda install -y python=3.9 && \
    conda clean -tipsy && \
    echo "PATH=/opt/miniconda3/bin:\${PATH}" > /etc/profile.d/miniconda.sh && \
    pip install --no-cache pyspark==${SPARK_VERSION} && \
    pip install -r requirements.txt && \
    python /opt/miniconda3/bin/find_spark_home.py && \
    SPARK_HOME=/opt/miniconda3/lib/python3.9/site-packages/pyspark && \
    echo "export SPARK_HOME=/opt/miniconda3/lib/python3.9/site-packages/pyspark" > /etc/profile.d/spark.sh && \
    curl -sLo $SPARK_HOME/jars/aws-java-sdk-1.7.4.jar https://repo1.maven.org/maven2/com/amazonaws/aws-java-sdk/1.7.4/aws-java-sdk-1.7.4.jar && \
    curl -sLo $SPARK_HOME/jars/hadoop-aws-2.7.3.jar https://repo1.maven.org/maven2/org/apache/hadoop/hadoop-aws/2.7.3/hadoop-aws-2.7.3.jar && \
    mkdir -p $SPARK_HOME/conf && \
    echo "spark.hadoop.fs.s3.impl=org.apache.hadoop.fs.s3a.S3AFileSystem" >> $SPARK_HOME/conf/spark-defaults.conf && \
    apt-get remove -y curl bzip2 && \
    apt-get autoremove -y && \
    apt-get clean && \
    ln -sf /bin/bash /bin/sh

# Start Python Script
CMD ["python", "-u", "Explainer.py"]