# niwl - a prototype system for open, decentralized, metadata resistant communication

**niwl** (_/nɪu̯l/_) - fog, mist or haze (Welsh).

**niwl** is an **experimental** bandwidth efficient anonymous communication system based on [fuzzytags](https://crates.io/crates/fuzzytags) in combination
with untrusted mixing nodes and an additional untrusted routing server.

This workspace provides a prototype set of libraries, clients and servers.

## Security (hic sunt dracones)

This crate workspace provides and documents a novel and highly experimental metadata resistant communication system.

The code has not undergone any significant review.

Further, it is based on an [experimental implementation (fuzzytags), of an experimental cryptographic scheme (FMD2)](https://git.openprivacy.ca/openprivacy/fuzzytags)
which also has a large list of security warnings.

I urge you to not rely on this code or derivative systems until it has been reviewed and given considerable thought. 

# Motivation

Instead of placing messages into deterministic buckets based on the recipient, [Fuzzy Message Detection](https://eprint.iacr.org/2021/089.pdf)  
allows each message to probabilistically address itself to several parties in addition to the intended party - 
utilizing the anonymity of the whole set of participants, instead of the ones who happen to share a bucket for a given round.

Unfortunately, naive deployments are [vulnerable to intersection attacks and statistical analysis](https://docs.openprivacy.ca/fuzzytags-book/simulation-eu-core-email.html)
which forces a requirement an additional layer of sender anonymity is necessary to prevent metadata analysis.

In order to obtain sender anonymity without introducing an external mix network or anonymizing overlay network such 
as tor or i2p, we can observe that clients are free to implement any behaviour they want directly on top of the 
fuzzy message detection system - and that includes mixing.


# How niwl Works

A niwl system relies on a single, untrusted routing server that acts as a bulletin board. We assume that clients
communicate with this server via https such that network adversaries are unable to determine the exact messages
sent and received by each client.

niwl clients can post and fetch messages to and from the server. When posting a message a client attaches a fuzzytag
generated for the receiver that allows the receiver to not only identify the message, but also to restrict the number
of other messages they have to download (see [Fuzzytags](https://docs.openprivacy.ca/fuzzytags-book/introduction.html) and [Fuzzy Message Detection](https://eprint.iacr.org/2021/089))

In order to provide statistical anonymity , the above base functionality is extended by a special class of client
called `random ejection mixers` or `REMs` for short.

`REMs` reinforce the anonymity of the system in two ways:

1. `REMs` download all the of messages from the server. Thus providing cover for receivers who download only a fraction 
   of the messages. A niwl server cannot distinguish between a message intended for a REM from a message intended for an
   ordinary client.
   
2. Clients can wrap messages to other clients in a message that is first forwarded to a `REM`. The `REM` then decrypts 
   the message and adds it to a store of messages - ejecting a previously stored message (at random) first to make space.
   
Note: This comes at the cost of doubling the traffic in the system (1 message to the REM and another message to
the end client). Fuzzy message detection allows clients to reduce the amount of messages they have to download.

## Random Ejection Mixers (REMs)

A REM starts with a store of `n` randomly generated messages with randomly generated fuzzytags. These messages are 
for all intents and purposes "noise". Each REM also generates a TaggingKey that it can provide (publicly or privately)
to other clients who wish to use the REMs services.

Each REM constantly checks the niwl Server for messages. It checks each message it downloads against its RootSecret
and if the FuzzyTag verifies then it proceeds to decrypt the message.

The primary service a REM provides is anonymous mixing. A decrypted mixpacket contains 2 fields:

1. The fuzzytag of the message to forward.
2. The message itself, which we will assume to be encrypted by some out-of-scope process.

Once a message is decrypted, an existing message from the store is randomly chosen to be ejected by the mix - and is
posted to the niwl Server. The new decrypted message takes its place in the message store.

### On the Privacy of REMs

Fuzzytags themselves can only be linked to receivers via those in position of a RootSecret *or* niwl Servers who
possess the `DetectionKey` - as such, assuming that there is no collusion between a particular REM and a niwl Server
there is no mechanism through which a REM can associate message with a (set of) receiver(s).

Further, (again assuming no collusion between a particular REM and a niwl Server), there is no mechanism for a REM to associate
a message with a particular sender.

Finally, and perhaps most importantly, there is no limit on the number of REMs permitted in a particular system. Different
parties can select different REMs with different trust valuations. REMs can join the system at any time without permission
from any other entity. In other words, unlike traditional mixnets or onion routing, the system does not rely on consensus
regarding the mixing entities to ensure privacy.

### On the Security of REMS

`n-1 attacks` / `flooding attacks` and other active attacks on mixers are a valid concern with any mixing strategy. 

This broad genre of attacks can be generalized as follows:

1. REMs start with a pool of randomly generated messages, this protected initial messages sent to the REM.
2. Over time this pool is probabilistically replaced by messages from the network.
3. A malicious niwl server, having identified a REM, can flood the REM with its own messages.
4. At a certain number of messages, the probability that a REM store contains only messages from the niwl server approaches 1.0.
5. A niwl server can then delay every other message sent to it by other clients one-by-one.
    1. If the message isn't for the REM then nothing will happen.
    2. If the message is for the REM then the REM will either eject a message known to the niwl Server, or it will eject
        an unknown message than the niwl Server can then correlate with a Sender and a set of Receivers.
       
Before diving into mitigation strategies it is worth outlining a few properties of niwl that differ from other
mixing-based anonymity systems.

0. Using REMs are not mandatory; parties may exchange messages with each other directly. Doing so does introduce a vulnerability
   to statistical analysis.
1. Different parties can rely on different REMs without compromising metadata privacy, and without negotiation.
2. If a REM becomes slow to respond or sends out and error alert, parties may choose to move to a different REM.
3. Different REMs can adopt different mixing strategies, and may be selective about what traffic they mix.

Additionally, we should also enumerate what could go wrong, in addition to an active attack on a particular mix.

The niwl server may deliberately drop or delay packets arbitrarily. Beyond this prototype it is worth considering 
incentive mechanisms such as ([token-based services](https://openprivacy.ca/research/OPTR2019-01/)) to mitigate this.

niwl may attempt to perform a "tagging attack" however there is nothing within the structure of niwl packets that
allows a tag to be placed on a message. The fuzzytags themselves will fail to verify if they are modified in any way,
and the ciphertext itself is bound to the fuzzytag both through the derived encryption key, and the nonce. And interference
with a packet is equivalent to dropping a packet.

Malicious entities can only tag their own message through the system (something that requires collusion to
take advantage of). (NOTE: this is functionally equivalent to Sphinx, and it might be worth just converting this
over to use Sphinx)

niwl servers may attempt to passively profile traffic originating from clients in an attempt to determine mixing nodes. 
REMs always download all messages from the niwl server and so the only available metadata exposed is the rate at which 
a REM *sends* messages. This can be partially mitigated by introducing random delays between individual sends, and between 
syncing periods.
   
REMs employ [heartbeat messages](references/heartbeat.pdf) (messages periodically sent to the niwl server addressed to the REM)
to detect such attacks. If a REM does not receive its own heartbeat message shortly after it is sent, it begins injecting random messages 
into its pool to thwart mixers. It can also display this status publicly and/or include the status in legitimate messages alerting 
other clients to the malicious niwl Server.

The rate at which a niwl sends out a heartbeat message is also a vector for passive profiling. Heartbeats must not
be distinguishable from other niwl traffic through their rate.

Finally, the fact that a REM operates 24/7 will make it stand out from a party that only uses the system for part
of the day (or week...etc.) - the only practical defense to this is to have more services and bots make use of the
niwl system other than mixers - as traffic diversity increases, the less utility tells like frequency of message
sends ultimately have.


### Encryption

For the purposes of this prototype message are encrypted using a simple one-use, unidirectional diffie-hellman derived key,
where the sending party generates an ephemeral keypair (which then uses libsodiums secretbox to perform the actual encryption). 
This key binds the message to a particular fuzzytag (which prevents tampering) but does nothing else to certify the
authenticity of the message.

Because of this only confidentiality and integrity of the message contents is asserted - no authentication mechanisms is provided. 
Any party that knows the `PublicKey` and the public `TaggingKey` of another party can encrypt and send messages to them,
and the recipient party has no mechanism to certify the origin of these messages.

Any applications built on top of niwl need to provide an additional encryption layer that provides authenticity
(e.g. a complete diffie-hellman key exchange involving pre=exchanged long term identity public keys).

### Notes on IP and other networking Metadata.

niwl is designed to provide metadata security when operated over an unprotected network. Ideally, a niwl server should
learn nothing about the habits of a particular IP address other than they are using niwl. In practice, as discussed above
a server can likely distinguish between automated services and manual clients.

Clients may wish to hide their use of niwl from a network adversary (at a risk of revealing that they are using another anonymizing network).
This will also further reduce the ability of niwl to correlate senders with specific behaviour and can be seen as
complimentary, but optional.

### Notes on future work and expansions

There is no reason that a client could chain a sequence of mixers together via onion encrypted their original
message to multiple mix nodes. In that sense we can treat the system as a superposition of free-route mix networks.

Analysis should be done to determine the anonymity of this system and the impact of added more mixers to the overall
anonymity of the fuzzy message detection.

# Code Overview

**niwl** provides common library functions useful to all other packages.

**niwl-server** provides a web server with a json API for posting new tags and querying the tags database.

**niwl-client** provides a command-line application for managing secrets, tagging keys of parties and posting / querying
for new tags.

**niwl-rem** provides an implementation of the random ejection mixer.

For a more detailed overview please check out each individual crate.

# Examples

## Simple Peer-to-Peer

    niwl-client alice.profile generate "alice"
    Tagging Key: auaaaaaaaaaaaylmnfrwkgaaaaaaaaaaadlbii3y7r6vmc7upbxa4myohaqmr5xl22bdxeed4abkotnovlmakzdo5stq2ibtjewm4rnkgzqwglrt72zfeyomvdpxqnu4ci4hwebyiseyn7pqfxypnvef7a3flu2hby7gdluh6wocxa5mvmimi2xorydcqaca2p2aevmue4cwyxnw2h7fkps7e6grgls66zgohbnwjibt6nlsdqjbrdjrzlsc3at3f43jyniz2i67ng6xdty5pr3elzedhjlvefhd6pjfc7g4owrz3dkq5xt2hhh3vvctkywqkcwriguayyx3pourepfs7s76bekrjgcjgj6zyid3ixmeh5ewqhkhxhzevf3uogvscxtpbksaclhccht7pj2fungnztfghshd6lsmegmysiiuyav6schtmyxmne2vfi4j4cxllm2crj3cqofsxjlxov3ms2zgtjzyxtubwtnwspc4jhijz4kufm6r3qkhpcyibx7ulceckx2a4g23tkhtgshtxq3fga7ptbhq5gcebwiq6cfolt4zbn72gbmtc43nw63vd4soxf4bnbhrykaoudfs3mh6laap6iwbngo4ylocs4w5hgd4t22yrtrmhkewsc2eytsosxyhaiuaww24mszscsojm2bcoldpokwuxbnfx7lgnzdcuae3y55zoen47noltjqgcpuqzl6upjcvutgvvro6nu2uyl36rcqmw2by2e45uqtsdnolbispxv2e5aeeuz5gytuf5f5e44nldmywtmxkfqfljml5gye6tj3qswmz6d36f2k4v7fbiuv7jzplzmghsgxvmq7fo3qp655obysbggkd3iqpk76p5umbpc2tk64oiklrponulkqf3v337aaxyn6nvzz2rpj3o374tftscsr7oilzkah63xpe2jc45dd4fuwxvlg3c33zgkminemqqfz7jdjtnawy77vpxxgnosbw4fwadhhggofmipboiqo55xygojdnfdkuzgfe4455sdqv5ytzdl55yuzlbdgsnwtgnfakmoyjhblzbuwohq7esayfxe72yqgci5dappiad7bc3ikfsydv5b7stifajkxuosu345upxg2hwzajj4uu7lxaykxgo22pslkxnidaoyevn3gamx63ec4fkhzguhbu6jt7pukr4rpafx24vd622f5wzux4corlxthjuhi2ewiu6laxx3aqfkzv2d2hhqzsac25vycmmxy
    niwl-client bob.profile generate "bob"
    Tagging Key: auaaaaaaaaaaaylmnfrwkgaaaaaaaaaaadlbii3y7r6vmc7upbxa4myohaqmr5xl22bdxeed4abkotnovlmakzdo5stq2ibtjewm4rnkgzqwglrt72zfeyomvdpxqnu4ci4hwebyiseyn7pqfxypnvef7a3flu2hby7gdluh6wocxa5mvmimi2xorydcqaca2p2aevmue4cwyxnw2h7fkps7e6grgls66zgohbnwjibt6nlsdqjbrdjrzlsc3at3f43jyniz2i67ng6xdty5pr3elzedhjlvefhd6pjfc7g4owrz3dkq5xt2hhh3vvctkywqkcwriguayyx3pourepfs7s76bekrjgcjgj6zyid3ixmeh5ewqhkhxhzevf3uogvscxtpbksaclhccht7pj2fungnztfghshd6lsmegmysiiuyav6schtmyxmne2vfi4j4cxllm2crj3cqofsxjlxov3ms2zgtjzyxtubwtnwspc4jhijz4kufm6r3qkhpcyibx7ulceckx2a4g23tkhtgshtxq3fga7ptbhq5gcebwiq6cfolt4zbn72gbmtc43nw63vd4soxf4bnbhrykaoudfs3mh6laap6iwbngo4ylocs4w5hgd4t22yrtrmhkewsc2eytsosxyhaiuaww24mszscsojm2bcoldpokwuxbnfx7lgnzdcuae3y55zoen47noltjqgcpuqzl6upjcvutgvvro6nu2uyl36rcqmw2by2e45uqtsdnolbispxv2e5aeeuz5gytuf5f5e44nldmywtmxkfqfljml5gye6tj3qswmz6d36f2k4v7fbiuv7jzplzmghsgxvmq7fo3qp655obysbggkd3iqpk76p5umbpc2tk64oiklrponulkqf3v337aaxyn6nvzz2rpj3o374tftscsr7oilzkah63xpe2jc45dd4fuwxvlg3c33zgkminemqqfz7jdjtnawy77vpxxgnosbw4fwadhhggofmipboiqo55xygojdnfdkuzgfe4455sdqv5ytzdl55yuzlbdgsnwtgnfakmoyjhblzbuwohq7esayfxe72yqgci5dappiad7bc3ikfsydv5b7stifajkxuosu345upxg2hwzajj4uu7lxaykxgo22pslkxnidaoyevn3gamx63ec4fkhzguhbu6jt7pukr4rpafx24vd622f5wzux4corlxthjuhi2ewiu6laxx3aqfkzv2d2hhqzsac25vycmmxy

    niwl-client alice.profile import-tagging-key amaaaaaaaaaaaytpmimaaaaaaaaaaafaukgy7543bcnjyq4jbthaovnfxtdnya3jajmbwa4t5gmihqgudbta4nzigrhzirkekers23ng2lr4zbjspthybajjj7vbwn6wnied27e2jvuipqbinru2q7eumgbt62spztz3rpslymv4iwsujozb7ylcfr7ugroilpgxzrjniussojm4q3kun247o4kqjzcrec4ohcuiyaiinourb7h7j4qjv4ne46xhnptwsfjr5s7yz2igqsbpvrqeiy5u6khmxwpi2jzxrnk5qlixewjcbe3zzy4qpxnl7ybdds6tld522amonc2dxncff2ihribsdnd5fc5dozqu2eqqxqmyvnd5pdngozhqikdc6ovj4uzf2ttabckbr4sim6z3fkl7kd5wqjjdaosahqsi67gy47q3vd3ubtu5btx2lmgkmyzm2wuupvwxxvc65lcxghm43bu4yah76jb3u36kg4nzdemuxewxcswofymuvdxh24uqyyhn7ymlr6mnuuk6g6acy4bcu7gsiacu3am6qwfve7s5wckgbaqc6veafbzynjmv6wubkleas2ghkirnl3pdznf37pyz62hkjssiqzqlduhkcyghdkdzccrtnesdkob447zlxaj2qz24chuxpy7hkffx64fi7aqzkpujifagrkcxvroq43wl2hme7udqcwpdjdtqm7yhnnanazuahtqlvf3ux7kvmidevorrgaiephptm7qgk7ezw6aa7o3fjyra7m3xknbmpniqa4dnwg44cfgbj2ln6kcecgat4d5cokabzk64jjhfq4m6upoptya4bjy2chdhged4jsqvp646u4klk5zk2fmhgf7l365k2g4z4i2u2dveajldebgnwc4esdrmequawk5sk6oskurfsuj6i4v7jzeqcd5hbujllka4dq3cn3hidx67jspqefnwj6yr7fvwjvvtjo3ri5wcqqd3m5kjrmhjuxbho7sl5xnhzntdtha7ldwml6xkwg3x7scsmhikvkrzfenggxccunpyp6cmsslblfbdrwvl4qurnrdg7wqtlgy6pfhjrqwqej26e7ddxwax34fagkgqksupdutbaq2juvicn7rq3xrxs6bi6a2ozdfdyfbtun5ckz6ln2jxyu254appisier35e3d6nmicywn5p7m32cvcct3ilub4ovk4jpuizegyudyrcgoud2rmuyei6fdgrbvtdqv7gqy6a
    Got: bob: 4211f14667b425649390eee099c4e84bf758a1a4e6375e23b50c6de347c25654

    niwl-client alice.profile tag-and-send bob 
    Tag for bob 7e441275a5c3f88606c34c3451a44eaeaa025680cfcb3d9db53992501cc22134 4f7a7f961bc19297fee98da5f8601aa8373429b80b10c55dbe8116aa8c497a0e 71d8da

    niwl-client bob.profile detect
    7e441275a5c3f88606c34c3451a44eaeaa025680cfcb3d9db53992501cc22134 4f7a7f961bc19297fee98da5f8601aa8373429b80b10c55dbe8116aa8c497a0e 71d8da

## Mix and Send

      // Create a mixer
      niwl-rem generate mixer
      <!--- snip key -->
      niwl-rem run
      [DEBUG] kicking off initial heartbeat...
      .....


      //  Alice imports a keyset for a mixer and sends a message to bob via the mixer using `tag-and-mix`
      niwl-client alice.niwl import-tagging-key auaaaaaaaaaaa3ljpbsxegaaaaaaaaaaabeiwbh2iiojfcurszypf4urscr5p7s6q7dzoeqyamrtx63hoakgogb7azd3ov37hippyqdar4povsf7oq25zogfr4qjabgzqcxedttrfceqffywwubechylxd4qzouedzkkhyg2f6e6aftdypvfoff6345li5hmfetjja6aswyffb5ngohin2cdg5qokko7s4kb7d7hb33ki6uuaenxi7neuden2fxxys3dczicfacw3iwhqw7kygs67kzre7tljrfktss4whzhurmozs4znyrnnjmzazsbrijl2fmcatc3v6ptxdpw35vt6zwnyz2l7fcpblmtrnthmrmxiej3hcvi5d7qiwj6s7wi2dygu2ref2o5jm2tug3lxgbbgqwsqvoo7d5eropddbkhcbr5pzls5nco5hkpnuubho54i4msm7kinzobnc5rgyduo2dpl6jo6pnlb7nckmpcgmcyrntg52xmvzhbxumrtiwvhxaqdscsrvgz7eg5szngetzsitpdfhycskxmnxwe6himyllywdxzalojuit5ap5ugfsmcmywn5hciwupx2y2asgjxowmhjhiubjph6b6y7jiuyqnyjjrwehotass4432hrilxzxzrmppdbt2yo3kfmdtxv5fseyp2k7ld2gr7z5ds3fxc5mtilvj3fzaw5tabhxtf73uykozbgjimzs7cfluhcmwitytjdw72r3ws552fjre6pq5jwx2ihd5u2odegvhq7wuqg5xmjvmayirqywobsdkm7szk7r5n4svoareaomq3cmmxwpv45ftfnp2adzmcb4bqzwvvwfsjjfsmepb7ocyw6bgy6hh7cugfafv6ww3pukhzydemisv67r4wbeoyhdebx2mp22wjcyqzcsa66k3k236uz7v3sf7n5577td52zjwiu27wiugehvymi3nnfm5qx3ps7ts7qkp6y2qqf4rdyg3z23oswhw6ku2nxlniesc4u6nhcg5h3olcrrbh4c3q3nyejnbs2msyxxuasofm6ayn5fl5rhomr74jzmp35xfzw7mu6uwciwbcommq733d3cvtpwhetcqjoxpbrydcdrhvux43ybbauc6aqkwlpoid7cfrycexadbe3ilmzlinpppr43k7y6cj3rewsu42gb5ici5a3sy7mk66xudceu3novaxdtscgucz3yy3jp26ovqqdmvedmgk33p6puqguhdwwuxqz6u5jyhjvxllg7w55xpptj64dphamnix3wxcjimginb7d2k7qz6ey
      Got: mixer: aa18c8597fd54a7779a0770c15ecbcc4d247009c007425172ba560b17f180516
      niwl-client alice.niwl tag-and-mix mixer bob  "Hello Mixnet"

      // Bob should receive the message some time later.
      niwl-client bob.niwl detect
      message: Hello Mixnet

## Acknowledgements

- Thanks to Erinn Atwater for helpful discussions.
- FuzzyTags is based on [Fuzzy Message Detection](https://eprint.iacr.org/2021/089) by Gabrielle Beck and Julia Len and Ian Miers and Matthew Green

## References

* Beck, Gabrielle, et al. "Fuzzy Message Detection."

* Danezis, George, and Len Sassaman. "Heartbeat traffic to counter (n-1) attacks: red-green-black mixes." Proceedings of the 2003 ACM workshop on Privacy in the electronic society. 2003.

* Sampigethaya, Krishna, and Radha Poovendran. "A survey on mix networks and their secure applications." Proceedings of the IEEE 94.12 (2006): 2142-2181.