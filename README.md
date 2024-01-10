# 🐝 tinyknock

eBPF (XDP) port knocking with a minimal firewall that filter the incoming traffic. It is compatible with the [knock](https://github.com/jvinet/knock) client.

The filtering is zero trust, it means there are zero ports allowed by default on the concerned protocol(s). Since the port knocking rules are applied at XDP level, it must take a decision on every incoming XDP packet.

The rules mechanism is inspired by [OpenState](https://sdn.ieee.org/newsletter/march-2017/openstate-an-interface-for-stateful-packet-processing-in-programmable-switches) but it is not designed for a switch.

> ⚠️ It is only experimental and should not run in production.
> 
> Note that every port knocking sequence starts with the port 0
> like `knock ipaddr 0 100 200 300`

## 📖 Build and run

You only need the following requirements (packages):
- `llvm`
- `clang`
- `make`
- `libcyaml`
- `libxdp`

### Debian / Ubuntu

```bash
apt install -y llvm clang make libcyaml-dev libxdp-dev
```

### RHEL / Fedora

```bash
dnf install -y llvm clang make libcyaml-devel libxdp-devel

# There are no official repositories for libcyaml
git clone https://github.com/tlsa/libcyaml
cd libcyaml
make VARIANT=release
make install VARIANT=release
cd ..
rm -rf libcyaml
```

You should also have `bpftool` if you need to debug.

To build, run the following command.
```bash
make
```

Then you can run.
```bash
./tinyknock -h
```

## 🤝 Contribute

If you want to help the project, you can follow the guidelines in [CONTRIBUTING.md](./CONTRIBUTING.md).

## 📏 YAML policies

Here is a full YAML schema:

```yaml
policies:
  - target: 8000
    action: open
    sequence:
      - value: 1000
        protocol: tcp
      - value: 2000
        protocol: udp
      - value: 3000
        protocol: tcp

  - target: 8000
    action: close
    sequence:
      - value: 3000
        protocol: tcp
      - value: 2000
        protocol: tcp
      - value: 1000
        protocol: tcp
```

Overview of the possible values and what it does:

```c
static const cyaml_strval_t action_strings[] = {
	{ "open", XDP_PASS },
	{ "close", XDP_DROP },
	{ "abort", XDP_ABORTED }
};

static const cyaml_strval_t protocol_strings[] = {
	{ "tcp", IPPROTO_TCP },
	{ "udp", IPPROTO_UDP },
	{ "icmp", IPPROTO_ICMP }
};
```

## ⭐ Use cases

To test the program, I have created two Linux network namespaces (both reachable by each other) following [this steps](https://medium.com/@technbd/creating-network-namespaces-in-linux-system-and-connecting-two-network-namespaces-using-virtual-6031d295f69b).

```bash
# Creates namespaces
ip netns add ns1
ip netns add ns2

# Creates two wirtual network interface peered
ip link add veth1 type veth peer name veth2

# Assigns virtual interface to the namespaces
ip link set veth1 netns ns1
ip link set veth2 netns ns2

# Assigns IP addresses to the virtual interfaces inside the namespaces
ip netns exec ns1 ip addr add 10.10.0.2/24 dev veth1
ip netns exec ns2 ip addr add 10.10.0.3/24 dev veth2

# Enables the virtual interfaces inside the namespaces
ip netns exec ns1 ip link set dev veth1 up
ip netns exec ns2 ip link set dev veth2 up
```

Now everything is setup, you can run the XDP program inside the first network namespace.

```bash
ip netns exec ns1 ./tinyknock -f file.yaml -b ./src/tinyknock.bpf.o -i veth1
```

And knock with the second one, assuming you have the following policies.
```yaml
policies:
  - target: 8000
    action: open
    sequence:
      - value: 1000
        protocol: tcp
      - value: 2000
        protocol: udp
      - value: 3000
        protocol: tcp
```

You can knock in the order above.
```bash
ip netns exec ns2 knock 10.10.0.2 0 1000 2000:udp 3000
```

If it worked, you should have a response like this:
```bash
ip netns exec ns2 knock 10.10.0.2 0 1000 2000:udp 3000

ip netns exec ns2 curl 10.10.0.2:8000
curl: (7) Failed to connect to 10.10.0.2 port 8000 after 0 ms: Couldn't connect to server
```

## 🎉 Tasks

- [ ] Support ICMP protocol
- [x] Implement the policies via YAML file
- [x] User log with a ring buffer
