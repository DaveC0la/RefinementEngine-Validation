FROM kathara/base
RUN apt-get update && apt-get install -y --no-install-recommends \
    apache2 libapache2-mod-security2 modsecurity-crs curl \
    && a2enmod proxy proxy_http security2 headers \
    && rm -rf /var/lib/apt/lists/*
