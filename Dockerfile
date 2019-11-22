FROM ubuntu:latest

RUN apt-get update -y && \
    apt-get install -y python3-pip python3

# We copy just the requirements.txt first to leverage Docker cache
COPY ./requirements.txt /app/requirements.txt
#ENTRYPOINT [ "python3" ]

WORKDIR /app

COPY . /app

EXPOSE 5000

RUN pip3 install -r requirements.txt

ENV LC_ALL=C.UTF-8

ENV LANG=C.UTF-8

CMD [ "flask", "run", "-h", "0.0.0.0" ]