"""forensic-evidence-toolkit (fet).

A small, dependency-free DFIR toolkit covering three evidence types:

* disk images      -> :mod:`fet.imaging`  (acquisition, hashing, chain of custody)
* NTFS ``$MFT``    -> :mod:`fet.mft`      (parsing, timelines, timestomp indicators)
* memory images    -> :mod:`fet.memory`   (Volatility 3 orchestration + triage rules)
                      :mod:`fet.strings_ioc` (string carving + IOC extraction)
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
