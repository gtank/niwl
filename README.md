# niwl - a prototype system for open, decentralized, metadata resistant communication

**niwl** (_/nɪu̯l/_) - fog, mist or haze (Welsh).

Privacy preserving applications often require a mechanism for providing notifications to parties that an
event has happened e.g. a new group message, a payment etc.  

**niwl** provides a set of libraries, clients and servers to provide this in a metadata resistant, bandwidth
efficient way based on [fuzzytags](https://crates.io/crates/fuzzytags).

# How Niwl Works

A Niwl system relies on a single, untrusted routing server that acts as a bulletin board.

Niwl clients can post and fetch messages to and from the server. When posting a message a client attaches a fuzzytag
generated for the receiver that allows the receiver to not only identify the message, but also to restrict the number
of other messages they have to download (see [Fuzzytags](https://docs.openprivacy.ca/fuzzytags-book/introduction.html) and [Fuzzy Message Detection](https://eprint.iacr.org/2021/089))

In order to provide statistical anonymity , the above base functionality is extended by a special class of client
called `random ejection mixers` or `REMs` for short.

`REMs` reinforce the anonymity of the system in two ways:

1. `REMs` download all the of messages from the server. Thus providing cover for receivers who download only a fraction 
   of the messages. A Niwl server cannot distinguish between a message intended for a REM from a message intended for an
   ordinary client.
   
2. Clients can wrap messages to other clients in a message that is first forwarded to a `REM`. The `REM` then decrypts 
   the message and adds it to a store of messages - ejecting a previously stored message (at random) first to make space.
   

## Random Ejection Mixers (REMs)

A REM starts with a store of `n` randomly generated messages with randomly generated fuzzytags. These messages are 
for all intents and purposes "noise". Each REM also generates a TaggingKey that it can provide (publicly or privately)
to other clients who wish to use the REMs services.

Each REM constantly checks the Niwl Server for messages. It checks each message it downloads against its RootSecret
and if the FuzzyTag verifies then it proceeds to decrypt the message.

The primary service a REM provides is anonymous mixing. A decrypted mixpacket contains 2 fields:

1. The fuzzytag of the message to forward.
2. The message itself, which we will assume to be encrypted by some out-of-scope process.

Once a message is decrypted, an existing message from the store is randomly chosen to be ejected by the mix - and is
posted to the Niwl Server. The new decrypted message takes its place in the message store.

### On the Privacy of REMs

Fuzzytags themselves can only be linked to receivers via those in position of a RootSecret *or* Niwl Servers who
possess the `VerificationKey` - as such, assuming that there is no collusion between a particular REM and a Niwl Server
there is no mechanism through which a REM can associate message with a (set of) receiver(s).

Further, (again assuming no collusion between a particular REM and a Niwl Server), there is no mechanism for a REM to associate
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
3. A malicious Niwl server, having identified a REM, can flood the REM with its own messages.
4. At a certain number of messages, the probability that a REM store contains only messages from the Niwl server approaches 1.0.
5. A Niwl server can then delay every other message sent to it by other clients one-by-one.
    1. If the message isn't for the REM then nothing will happen.
    2. If the message is for the REM then the REM will either eject a message known to the Niwl Server, or it will eject
        an unknown message than the Niwl Server can then correlate with a Sender and a set of Receivers.

First, we should note that Niwl is less prone to these kinds of attacks because:

1. REMs are not, a-priori, known to the Niwl Server and such are more difficult to target than mixers in traditional mixnets.
2. Different parties can rely on different REMs without compromising metadata privacy.

As such targeting a particular mix is not an effective strategy for undermining the anonymity set of the entire system.

Further, REMs employ [heartbeat messages](references/heartbeat.pdf) (messages periodically sent to the Niwl server addressed to the REM)
to detect such attacks. If a REM does not receive its own heartbeat message shortly after it is sent, it begins injecting random messages
   into its pool to thwart mixers. It can also display this status publicly and/or include the status in legitimate messages alerting
   other clients to the malicious Niwl Server


# Code Overview

**niwl** provides common library functions useful to all other packages.

**niwl-server** provides a web server with a json API for posting new tags and querying the tags database.

**niwl-client** provides a command-line application for managing secrets, tagging keys of parties and posting / querying
for new tags.

**niwl-rem** provides an implementation of the random ejection mixer.

For a more detailed overview please check out each individual crate.

# Example


    niwl-client alice.profile generate "alice"
    Tagging Key: auaaaaaaaaaaaylmnfrwkgaaaaaaaaaaadlbii3y7r6vmc7upbxa4myohaqmr5xl22bdxeed4abkotnovlmakzdo5stq2ibtjewm4rnkgzqwglrt72zfeyomvdpxqnu4ci4hwebyiseyn7pqfxypnvef7a3flu2hby7gdluh6wocxa5mvmimi2xorydcqaca2p2aevmue4cwyxnw2h7fkps7e6grgls66zgohbnwjibt6nlsdqjbrdjrzlsc3at3f43jyniz2i67ng6xdty5pr3elzedhjlvefhd6pjfc7g4owrz3dkq5xt2hhh3vvctkywqkcwriguayyx3pourepfs7s76bekrjgcjgj6zyid3ixmeh5ewqhkhxhzevf3uogvscxtpbksaclhccht7pj2fungnztfghshd6lsmegmysiiuyav6schtmyxmne2vfi4j4cxllm2crj3cqofsxjlxov3ms2zgtjzyxtubwtnwspc4jhijz4kufm6r3qkhpcyibx7ulceckx2a4g23tkhtgshtxq3fga7ptbhq5gcebwiq6cfolt4zbn72gbmtc43nw63vd4soxf4bnbhrykaoudfs3mh6laap6iwbngo4ylocs4w5hgd4t22yrtrmhkewsc2eytsosxyhaiuaww24mszscsojm2bcoldpokwuxbnfx7lgnzdcuae3y55zoen47noltjqgcpuqzl6upjcvutgvvro6nu2uyl36rcqmw2by2e45uqtsdnolbispxv2e5aeeuz5gytuf5f5e44nldmywtmxkfqfljml5gye6tj3qswmz6d36f2k4v7fbiuv7jzplzmghsgxvmq7fo3qp655obysbggkd3iqpk76p5umbpc2tk64oiklrponulkqf3v337aaxyn6nvzz2rpj3o374tftscsr7oilzkah63xpe2jc45dd4fuwxvlg3c33zgkminemqqfz7jdjtnawy77vpxxgnosbw4fwadhhggofmipboiqo55xygojdnfdkuzgfe4455sdqv5ytzdl55yuzlbdgsnwtgnfakmoyjhblzbuwohq7esayfxe72yqgci5dappiad7bc3ikfsydv5b7stifajkxuosu345upxg2hwzajj4uu7lxaykxgo22pslkxnidaoyevn3gamx63ec4fkhzguhbu6jt7pukr4rpafx24vd622f5wzux4corlxthjuhi2ewiu6laxx3aqfkzv2d2hhqzsac25vycmmxy
    niwl-client bob.profile generate "bob"
    Tagging Key: auaaaaaaaaaaaylmnfrwkgaaaaaaaaaaadlbii3y7r6vmc7upbxa4myohaqmr5xl22bdxeed4abkotnovlmakzdo5stq2ibtjewm4rnkgzqwglrt72zfeyomvdpxqnu4ci4hwebyiseyn7pqfxypnvef7a3flu2hby7gdluh6wocxa5mvmimi2xorydcqaca2p2aevmue4cwyxnw2h7fkps7e6grgls66zgohbnwjibt6nlsdqjbrdjrzlsc3at3f43jyniz2i67ng6xdty5pr3elzedhjlvefhd6pjfc7g4owrz3dkq5xt2hhh3vvctkywqkcwriguayyx3pourepfs7s76bekrjgcjgj6zyid3ixmeh5ewqhkhxhzevf3uogvscxtpbksaclhccht7pj2fungnztfghshd6lsmegmysiiuyav6schtmyxmne2vfi4j4cxllm2crj3cqofsxjlxov3ms2zgtjzyxtubwtnwspc4jhijz4kufm6r3qkhpcyibx7ulceckx2a4g23tkhtgshtxq3fga7ptbhq5gcebwiq6cfolt4zbn72gbmtc43nw63vd4soxf4bnbhrykaoudfs3mh6laap6iwbngo4ylocs4w5hgd4t22yrtrmhkewsc2eytsosxyhaiuaww24mszscsojm2bcoldpokwuxbnfx7lgnzdcuae3y55zoen47noltjqgcpuqzl6upjcvutgvvro6nu2uyl36rcqmw2by2e45uqtsdnolbispxv2e5aeeuz5gytuf5f5e44nldmywtmxkfqfljml5gye6tj3qswmz6d36f2k4v7fbiuv7jzplzmghsgxvmq7fo3qp655obysbggkd3iqpk76p5umbpc2tk64oiklrponulkqf3v337aaxyn6nvzz2rpj3o374tftscsr7oilzkah63xpe2jc45dd4fuwxvlg3c33zgkminemqqfz7jdjtnawy77vpxxgnosbw4fwadhhggofmipboiqo55xygojdnfdkuzgfe4455sdqv5ytzdl55yuzlbdgsnwtgnfakmoyjhblzbuwohq7esayfxe72yqgci5dappiad7bc3ikfsydv5b7stifajkxuosu345upxg2hwzajj4uu7lxaykxgo22pslkxnidaoyevn3gamx63ec4fkhzguhbu6jt7pukr4rpafx24vd622f5wzux4corlxthjuhi2ewiu6laxx3aqfkzv2d2hhqzsac25vycmmxy

    niwl-client alice.profile import-tagging-key amaaaaaaaaaaaytpmimaaaaaaaaaaafaukgy7543bcnjyq4jbthaovnfxtdnya3jajmbwa4t5gmihqgudbta4nzigrhzirkekers23ng2lr4zbjspthybajjj7vbwn6wnied27e2jvuipqbinru2q7eumgbt62spztz3rpslymv4iwsujozb7ylcfr7ugroilpgxzrjniussojm4q3kun247o4kqjzcrec4ohcuiyaiinourb7h7j4qjv4ne46xhnptwsfjr5s7yz2igqsbpvrqeiy5u6khmxwpi2jzxrnk5qlixewjcbe3zzy4qpxnl7ybdds6tld522amonc2dxncff2ihribsdnd5fc5dozqu2eqqxqmyvnd5pdngozhqikdc6ovj4uzf2ttabckbr4sim6z3fkl7kd5wqjjdaosahqsi67gy47q3vd3ubtu5btx2lmgkmyzm2wuupvwxxvc65lcxghm43bu4yah76jb3u36kg4nzdemuxewxcswofymuvdxh24uqyyhn7ymlr6mnuuk6g6acy4bcu7gsiacu3am6qwfve7s5wckgbaqc6veafbzynjmv6wubkleas2ghkirnl3pdznf37pyz62hkjssiqzqlduhkcyghdkdzccrtnesdkob447zlxaj2qz24chuxpy7hkffx64fi7aqzkpujifagrkcxvroq43wl2hme7udqcwpdjdtqm7yhnnanazuahtqlvf3ux7kvmidevorrgaiephptm7qgk7ezw6aa7o3fjyra7m3xknbmpniqa4dnwg44cfgbj2ln6kcecgat4d5cokabzk64jjhfq4m6upoptya4bjy2chdhged4jsqvp646u4klk5zk2fmhgf7l365k2g4z4i2u2dveajldebgnwc4esdrmequawk5sk6oskurfsuj6i4v7jzeqcd5hbujllka4dq3cn3hidx67jspqefnwj6yr7fvwjvvtjo3ri5wcqqd3m5kjrmhjuxbho7sl5xnhzntdtha7ldwml6xkwg3x7scsmhikvkrzfenggxccunpyp6cmsslblfbdrwvl4qurnrdg7wqtlgy6pfhjrqwqej26e7ddxwax34fagkgqksupdutbaq2juvicn7rq3xrxs6bi6a2ozdfdyfbtun5ckz6ln2jxyu254appisier35e3d6nmicywn5p7m32cvcct3ilub4ovk4jpuizegyudyrcgoud2rmuyei6fdgrbvtdqv7gqy6a
    Got: bob: 4211f14667b425649390eee099c4e84bf758a1a4e6375e23b50c6de347c25654

    niwl-client alice.profile tag-and-send bob 
    Tag for bob 7e441275a5c3f88606c34c3451a44eaeaa025680cfcb3d9db53992501cc22134 4f7a7f961bc19297fee98da5f8601aa8373429b80b10c55dbe8116aa8c497a0e 71d8da

    niwl-client bob.profile detect 10
    7e441275a5c3f88606c34c3451a44eaeaa025680cfcb3d9db53992501cc22134 4f7a7f961bc19297fee98da5f8601aa8373429b80b10c55dbe8116aa8c497a0e 71d8da

## References

* Danezis, George, and Len Sassaman. "Heartbeat traffic to counter (n-1) attacks: red-green-black mixes." Proceedings of the 2003 ACM workshop on Privacy in the electronic society. 2003.