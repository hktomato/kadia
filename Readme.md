#KADIA: Interface Recovery Module for Driver Fuzz Testing
This framework recovers driver's IRP communication interface.
It can be used for driver fuzz testing.

##Dependency
We recommend python3.8 virtual environment to use KADIA.
~~~{.sh}
# install virtualenv
$ pip3 install virtualenv
$ pip3 install virtualenvwrapper

# make virtual environment
$ virtualenv [virtual env name]
$ source [virtual env name]/bin/activate

$ deactivate
~~~

It requires angr, radare2 to use symbolic-analysis and static-analysis.
~~~{.sh}
# use symbolic-analysis
$ pip3 install angr
$ pip3 install boltons

# use static-analysis 
$ apt install radare2
~~~
