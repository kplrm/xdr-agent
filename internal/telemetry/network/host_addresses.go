package network

import (
	"context"
	"log"
	"maps"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

type hostIPSet map[netip.Addr]struct{}

// HostAddresses shares exact interface IPs without querying the kernel per event.
type HostAddresses struct {
	current atomic.Pointer[hostIPSet]
	read    func() ([]net.Addr, error)
}

// WatchHostAddresses caches local addresses and follows kernel address changes.
// The returned stop function cancels and joins the watcher.
func WatchHostAddresses(ctx context.Context) (*HostAddresses, func()) {
	hosts := &HostAddresses{read: net.InterfaceAddrs}
	hosts.refresh()
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := hosts.watch(ctx); err != nil && ctx.Err() == nil {
			log.Printf("network addresses: notifications unavailable, refreshing locally every minute: %v", err)
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					hosts.refresh()
				}
			}
		}
	}()
	return hosts, func() { cancel(); <-done }
}

func (h *HostAddresses) refresh() {
	addresses, err := h.read()
	if err != nil {
		log.Printf("network addresses: retaining previous addresses: %v", err)
		return
	}
	next := make(hostIPSet, len(addresses))
	for _, address := range addresses {
		var ip net.IP
		switch address := address.(type) {
		case *net.IPNet:
			ip = address.IP
		case *net.IPAddr:
			ip = address.IP
		}
		if addr, ok := netip.AddrFromSlice(ip); ok {
			addr = addr.Unmap()
			if !addr.IsUnspecified() && !addr.IsMulticast() {
				next[addr] = struct{}{}
			}
		}
	}
	if previous := h.current.Load(); previous == nil || !maps.Equal(*previous, next) {
		h.current.Store(&next)
	}
}

func (h *HostAddresses) watch(ctx context.Context) error {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK, Groups: unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR,
	}); err != nil {
		unix.Close(fd)
		return err
	}
	file := os.NewFile(uintptr(fd), "interface-address-changes")
	defer file.Close()
	stop := context.AfterFunc(ctx, func() { file.Close() })
	defer stop()
	// Subscribe before refreshing so changes during initial discovery are queued.
	h.refresh()
	buffer := make([]byte, 32*1024)
	for ctx.Err() == nil {
		// Periodic resync also repairs missed notifications; no internet is used.
		if err := file.SetReadDeadline(time.Now().Add(time.Minute)); err != nil {
			return err
		}
		if _, err := file.Read(buffer); err != nil && !os.IsTimeout(err) {
			return err
		}
		h.refresh()
	}
	return nil
}
