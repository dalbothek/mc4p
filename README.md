## What is mc4p?

mc4p (short for Minecraft Portable Protocol-Parsing Proxy) is a Minecraft proxy
server. With mc4p, you can create programs (mc4p plugins) that examine
and modify messages sent between the Minecraft client and server without
writing any multi-threaded or network-related code.

### Installing from source

To install from source, just clone the GitHub repository. You can then install
it in 'development' mode with

    python setup.py develop

If mc4p is installed in 'development' mode, you can uninstall it with

    python setup.py develop --uninstall

### Dependencies

* [Python 2.7](http://www.python.org/download/releases/2.7.3/)
* [setuptools](http://pypi.python.org/pypi/setuptools)

#### Linux / Mac OS X
* [libevent](http://libevent.org/)

#### Windows
* [gevent](https://github.com/SiteSupport/gevent/downloads)


## License

mc4p is licensed under the [Do What The Fuck You Want
To Public License](http://www.wtfpl.net/txt/copying/), Version 2,
as published by Sam Hocevar
