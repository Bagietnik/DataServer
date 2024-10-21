FROM gcc:latest

WORKDIR /usr/src/app

COPY . .

RUN apt-get update && apt-get install -y libssl-dev

RUN gcc -o serverMBD serverMBD.c -lssl -lcrypto

EXPOSE 9999

CMD ["./serverMBD"]
