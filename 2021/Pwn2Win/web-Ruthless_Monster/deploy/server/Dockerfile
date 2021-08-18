FROM privatebin/nginx-fpm-alpine

COPY html /var/www

USER root

RUN chown root:root -R /var/www
RUN chown root:root -R /srv/
RUN chmod 755 -R /srv/
RUN chmod 755 -R /var/www
RUN chmod 777 -R /srv/data/

WORKDIR /root
RUN apk add perl make
RUN wget https://exiftool.org/Image-ExifTool-12.23.tar.gz && tar -xzf Image-ExifTool-12.23.tar.gz &&
rm Image-ExifTool-12.23.tar.gz &&\
cd Image-ExifTool-12.23 && perl Makefile.PL && make test && make install && mkdir /uploads && chmod
777 /uploads

WORKDIR /var/www
USER 65534:82
