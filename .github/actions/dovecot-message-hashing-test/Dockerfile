FROM debian:buster-slim

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt-get install -y \
        curl \
        gpg

RUN curl https://repo.dovecot.org/DOVECOT-REPO-GPG | gpg --import && \
        gpg --export ED409DA1 > /etc/apt/trusted.gpg.d/dovecot.gpg && \
        echo "deb https://repo.dovecot.org/ce-2.3-latest/debian/buster buster main" >> /etc/apt/sources.list.d/dovecot.list

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
	git \
	automake \
	libtool \
	make \
	build-essential \
	pkg-config \
	dovecot-core \
	dovecot-dev

RUN git clone https://github.com/slusarz/dovecot-message-hashing.git /dovecot/message-hashing
WORKDIR /dovecot/message-hashing
RUN ./autogen.sh && \
	./configure --with-dovecot=/usr/lib/dovecot && \
	make install

# Users dovecot and dovenull are created by dovecot-core package
RUN useradd vmail && \
    mkdir -p /dovecot/sdbox && \
    chown -R vmail:vmail /dovecot/sdbox

ADD dovecot.conf /etc/dovecot/dovecot.conf
ADD test.eml /dovecot/test.eml

ADD entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
