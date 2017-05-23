# AMaViSd for Peekaboo # 

## Download Upstream Version ##

```shell
curl https://www.ijs.si/software/amavisd/amavisd-new-2.11.0.tar.xz -o amavisd-new-2.11.0.tar.xz
```

## Extract Necessary Files ##

```shell
tar xvf amavisd-new-2.11.0.tar.xz  amavisd-new-2.11.0/amavisd.conf-default
tar xvf amavisd-new-2.11.0.tar.xz  amavisd-new-2.11.0/amavisd
```

## Apply the Patch ##

```shell
cd amavisd-new-2.11.0/

patch -p4 < ../../peekaboo-amavisd.patch
patch -p1 < ../../debian-find_config_files.patch
```

## Use ##

```shell
configure and run
```