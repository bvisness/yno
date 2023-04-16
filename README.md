# y no server?

`yno` automatically troubleshoots your server. `yno` will look up DNS, find external IPs, and trace packets to figure out exactly where your connection is breaking down.

`yno` should be run **from the server you are trying to connect to.** It assumes you at least have shell access and are trying to get other stuff to work.

**DISCLAIMER:** `yno` is a jam project and is therefore woefully incomplete. Don't expect it to actually work.

## Building

Since `yno` is a jam project, it has some extra dependencies that could be avoided in future versions.

You will need the following command-line programs:

- `tcpdump`
- `ss`

You will also need `libpcap-dev`:

```
sudo apt install libpcap-dev
```

Then, if you have a sufficiently recent version of [Go](https://go.dev/), you can install it from source:

```
go install github.com/bvisness/yno
```

`yno` has only been tested on Ubuntu 22.04.

## Running

```
yno localhost:8080
yno mywebsite.com
```

## Jam Info

`yno` is a submission for the Handmade Network's 2023 [Visibility Jam](https://handmade.network/jam/visibility-2023). Its goal is to make your network problems visible and save you from having to remember so many arcane commands for completely routine work. In the future, maybe systems like `yno` could be persistently running to help you find and fix network issues much more quickly!
