# TLSential
TLSential is a server for providing short-lived, non-wildcard domains to all services within a firewall restricted network.

[![<ImageWare>](https://circleci.com/gh/ImageWare/TLSential.svg?style=svg)](https://app.circleci.com/pipelines/github/ImageWare/TLSential/)

# Building

Clone the repo. From the root directory, run `go build`. You should now have a binary in the root directory, `TLSential`.

# Running TLSential

You can run it with the default settings by just executing ./TLSential from the root directory. You can configure the server's port by using the `--port [port]` parameter.

# Building TLSential assets

### Development
There are a few commands to aid in building for development:
To build assets for development once:
```npm run dev```

To build assets and watch for changes:
```npm run watch```

To build assets with hot reloading (You need to use the domain outputted in the 'hot' file for your assets in development for this to work):
```npm run hot```

!! Note after starting the HMR hot reloading server you must restart the TLSential process on a port other than 8080:
```go build && ./TLSential.exe --port 8000 --no-https```\

!! Note 2 Once you're done with hot reloading you will need to rebuild for dev or prod to see your changes. This is because you need to rebuild assets and restart TLSential to clear out the hot config file

To build assets for production:
```npm run prod```


# Contributors

* Lead Developer - [d1str0](https://github.com/d1str0)
* Developer - [debus](https://github.com/debus)
* UI Designer - [domshyra](https://github.com/domshyra)
* Graphic Designer - [brooks42](https://github.com/brooks42)
