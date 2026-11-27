# Changelog

## 0.1.1 (2026-11-27)


### ⚠ BREAKING CHANGES

* **admission:** an administrator admits a direct device member of another space with no code and no peer, and a waiting welcome is kept at rest ([#47](https://github.com/transcodeworks/frasil/issues/47))
* **sync:** a member announces each blob that becomes whole at it, answers ObjectMissing for one it no longer holds, and a read no member will serve ends at once ([#48](https://github.com/transcodeworks/frasil/issues/48))
* **bindings:** Swift and Kotlin read a blob that is not whole here through a reader, and say what the device keeps of its blobs ([#45](https://github.com/transcodeworks/frasil/issues/45))
* **sync:** a blob dropped or evicted is asked again of the member that announced it ([#43](https://github.com/transcodeworks/frasil/issues/43))
* **relay:** an open peer with libraries on names its open library, and does not start without one ([#37](https://github.com/transcodeworks/frasil/issues/37))
* **blobs:** a reader gives any range of a blob that is not whole here, as its chunks arrive and open ([#36](https://github.com/transcodeworks/frasil/issues/36))
* **blobs:** a blob is kept, cached or absent, and a read fetches it into a cache with a budget ([#35](https://github.com/transcodeworks/frasil/issues/35))
* **objects:** fetch any chunks of an object, on tasks beside the connection ([#33](https://github.com/transcodeworks/frasil/issues/33))

### Features

* **admission:** an administrator admits a direct device member of another space with no code and no peer, and a waiting welcome is kept at rest ([#47](https://github.com/transcodeworks/frasil/issues/47)) ([09c9de7](https://github.com/transcodeworks/frasil/commit/09c9de76aee7e4279011bebdc9863b2e9c06abc9))
* **bindings:** Swift and Kotlin admit a device into a space over a nearby connection, and can abandon an admission ([#39](https://github.com/transcodeworks/frasil/issues/39)) ([5709bc8](https://github.com/transcodeworks/frasil/commit/5709bc8e99173000ea78337c6b46ebd3f892347c))
* **bindings:** Swift and Kotlin read a blob that is not whole here through a reader, and say what the device keeps of its blobs ([#45](https://github.com/transcodeworks/frasil/issues/45)) ([300bff1](https://github.com/transcodeworks/frasil/commit/300bff109aa6f1255d43ff117e785575a505f33e))
* **blobs:** a blob is kept, cached or absent, and a read fetches it into a cache with a budget ([#35](https://github.com/transcodeworks/frasil/issues/35)) ([d79f174](https://github.com/transcodeworks/frasil/commit/d79f174d67b7d871e120ba4efd4f11ffdf831850))
* **blobs:** a reader gives any range of a blob that is not whole here, as its chunks arrive and open ([#36](https://github.com/transcodeworks/frasil/issues/36)) ([5d93897](https://github.com/transcodeworks/frasil/commit/5d93897a79017129908269db6f7af9688a8277c5))
* **blobs:** a store with no room for a chunk makes the cache give way, and the read goes on through memory ([#41](https://github.com/transcodeworks/frasil/issues/41)) ([4306db0](https://github.com/transcodeworks/frasil/commit/4306db04afb0e16a11727b77b0ab933f5bbfe8cd))
* **blobs:** put, upload and read large objects a few chunks at a time ([#29](https://github.com/transcodeworks/frasil/issues/29)) ([3b64a4c](https://github.com/transcodeworks/frasil/commit/3b64a4c7fbc3e20c3902c757fe006c6af4c1ddd2))
* Frasil, protocol 1 ([57a8fee](https://github.com/transcodeworks/frasil/commit/57a8feef61027b887597f892c15cb2213ae477ce))
* **objects:** fetch any chunks of an object, on tasks beside the connection ([#33](https://github.com/transcodeworks/frasil/issues/33)) ([331f087](https://github.com/transcodeworks/frasil/commit/331f0877c17d42d79d9a4eeb8cfe77f3efd756d2))
* **sync:** a member announces each blob that becomes whole at it, answers ObjectMissing for one it no longer holds, and a read no member will serve ends at once ([#48](https://github.com/transcodeworks/frasil/issues/48)) ([49b183b](https://github.com/transcodeworks/frasil/commit/49b183be87ce553f7f5eacc4a45a51f47ea59f54))
* **wasm:** a browser reads blobs it does not hold, keeps its cache within the browser's quota, and plays them in media elements ([#44](https://github.com/transcodeworks/frasil/issues/44)) ([0163bea](https://github.com/transcodeworks/frasil/commit/0163bea827fa09ea784a893bda1affe5b1290ed6))


### Bug fixes

* **at-rest:** allow a restored device to finish creating a new space ([#27](https://github.com/transcodeworks/frasil/issues/27)) ([06f9b91](https://github.com/transcodeworks/frasil/commit/06f9b91a15db4f361b5308a5d685cb3180205731)), closes [#26](https://github.com/transcodeworks/frasil/issues/26)
* **blobs:** drop_local is not refused on account of a read that has returned, and waits for parts still being written ([#49](https://github.com/transcodeworks/frasil/issues/49)) ([8a34082](https://github.com/transcodeworks/frasil/commit/8a340828eb4edd8a26b17bcbdd97fded20de886a))
* **ephemeral:** a member connection sends its live slots once both sides have admitted ([#11](https://github.com/transcodeworks/frasil/issues/11)) ([ff7f17f](https://github.com/transcodeworks/frasil/commit/ff7f17f2ed7d4d885767ff29035537c016ae495a))
* **member:** two devices sync every space they share on a local network, not only the four announced ([#38](https://github.com/transcodeworks/frasil/issues/38)) ([afd72b0](https://github.com/transcodeworks/frasil/commit/afd72b08ebf27ddb7d41c4c1bde4536fd6010cc7))
* reduce client stack use in debug builds ([#17](https://github.com/transcodeworks/frasil/issues/17)) ([5546c9e](https://github.com/transcodeworks/frasil/commit/5546c9eef0ec5b619b53a9dec8d4abc6aec8ac26))
* **relay:** an open peer with libraries on names its open library, and does not start without one ([#37](https://github.com/transcodeworks/frasil/issues/37)) ([f74a9fc](https://github.com/transcodeworks/frasil/commit/f74a9fc51629a6c6ecaaaf060707a9c4ab8c0196))
* **sync:** a blob dropped or evicted is asked again of the member that announced it ([#43](https://github.com/transcodeworks/frasil/issues/43)) ([7bf3dc9](https://github.com/transcodeworks/frasil/commit/7bf3dc9f2af0f82c108fa22cb28e115e9fd78b4e))

## Changelog

Changes to the `frasil` crate's public API and to `@frasil/client` that an
application may need to act on.
