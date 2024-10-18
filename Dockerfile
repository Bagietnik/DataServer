FROM gcc:latest

WORKDIR /usr/src/app

COPY . .

RUN apt-get update && apt-get install -y libssl-dev

RUN gcc -o server server.c -lssl -lcrypto -lpthread

EXPOSE 9999

CMD ["./server"]
