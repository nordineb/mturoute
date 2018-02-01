# MTUROUTE

This is a fork of MTUROUTE from Eli Fulkerson (elifulkerson.com)

## Build

```
msbuild /t:rebuild mturoute.sln
```

## Alternative

```
docker run -it alpine
  / # apk add --no-cache iputils
  / # tracepath -n -p 80 google.com
```
