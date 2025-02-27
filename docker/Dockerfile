# contains all the docker analysis code
FROM python:3
LABEL maintainer="hardaker@isi.edu"

RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y zip

# python reqs for /usr/bin/python
RUN pip install traffic-taffy

# installs for system python
# RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y python3-yaml python3-numpy python3-matplotlib

COPY ./taffy-wrapper.sh /usr/bin/
RUN chmod a+x /usr/bin/taffy-wrapper.sh

ENTRYPOINT ["/usr/bin/taffy-wrapper.sh"]
CMD []
