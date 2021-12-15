try:
    from tinyBT.dht import main
    from tinyBT._version import __version__
except:
    from dht import main
    from _version import __version__

__all__ = (
    main, __version__
)
