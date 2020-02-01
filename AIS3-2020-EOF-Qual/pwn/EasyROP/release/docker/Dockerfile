FROM ubuntu:18.04
MAINTAINER Billy
RUN dpkg --add-architecture i386
RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install xinetd -y
RUN apt-get install libc6:i386 libncurses5:i386 libstdc++6:i386 libseccomp2:i386 python -y
RUN useradd -m EasyROP
COPY ./share /home/EasyROP
COPY ./xinetd /etc/xinetd.d/EasyROP
COPY ./flag /home/EasyROP/flag
RUN chmod 774 /tmp
RUN chmod -R 774 /var/tmp
RUN chmod -R 774 /dev
RUN chmod -R 774 /run
RUN chmod 1733 /tmp /var/tmp /dev/shm
RUN chown -R root:root /home/EasyROP
CMD ["/usr/sbin/xinetd","-dontfork"]
