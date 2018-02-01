# MTUROUTE

This is a fork of MTUROUTE from Eli Fulkerson (elifulkerson.com)

## Build

```
msbuild /t:rebuild mturoute.sln
```

## Alternative

ICMP protocol is not permitted through  Azure load balancers, so it's not possible to use mturoute. Instead, it's possible to use tracepath with the option -p
```
docker run -it alpine
  / # apk add --no-cache iputils
  / # tracepath -n -p 80 google.com
```
