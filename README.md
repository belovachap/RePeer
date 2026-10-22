# RePeer, A Peercoin Client for Debian amd64

## What is Peercoin?

[Peercoin](https://peercoin.net) (abbreviated PPC), previously known as PPCoin, is the first [cryptocurrency](https://en.wikipedia.org/wiki/Cryptocurrency) design introducing [proof-of-stake consensus](https://peercoin.net/resources#whitepaper) as a security model, with a combined [proof-of-stake](https://peercoin.net/resources#whitepaper)/[proof-of-work](https://en.wikipedia.org/wiki/Proof-of-work_system) minting system. Peercoin is based on [Bitcoin](https://bitcoin.org), while introducing many important innovations to cryptocurrency field including new security model, energy efficiency, better minting model and more adaptive response to rapid change in network computation power.

## What is RePeer?

RePeer is a descendant of the Peercoin Core code base starting at the v0.15.2ppc tag.

It assumes a specific target environment, Debian amd64, which helps reduce the complexity of the underlying C++ code and build setup.

## Branches and Tags

RePeer is tightly coupled to Debian releases. For example, you will find the "repeer-13" branch which assumes it is being built against Debian 13 (Trixie).

Within a branch there are tags to mark points fit for end users.
For example, you will find the "v13.0.1" tag which assumes it is being built against Debian 13 (Trixie) and is at a commit that is considered usable.

## Building

RePeer uses libraries that come in the standard Debian apt repositories.
You can easily install the necessary dependencies and compile the client yourself by following BUILD.md.
