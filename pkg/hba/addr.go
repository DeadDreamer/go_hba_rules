package hba

import (
	"fmt"
	"net"
	"strings"
)

// AddrSet описывает набор адресов/сетей правила после нормализации.
// Храним исходный токен для сообщений, и CIDR-маски для операций superset/overlap.
type AddrSet struct {
	Any       bool         // true если all/any (0.0.0.0/0 ::/0)
	Special   string       // samehost/samenet (при необходимости)
	Networks  []*net.IPNet // конкретные сети (IPv4 или IPv6)
	HasIPv4   bool
	HasIPv6   bool
	OrigToken string // оригинальное значение для сообщений
}

// ParseAddr разбирает адресное поле (CIDR/IP/all/samehost/...).
// Возвращает AddrSet с нормализованными сетями.
func ParseAddr(token string) (AddrSet, error) {
	addr := AddrSet{OrigToken: token}
	s := strings.ToLower(strings.TrimSpace(token))
	switch s {
	case "all":
		addr.Any = true
		return addr, nil
	case "samehost":
		addr.Special = "samehost"
		v4 := mustCIDR("127.0.0.1/32")
		v6 := mustCIDR("::1/128")
		addr.Networks = []*net.IPNet{v4, v6}
		addr.HasIPv4 = true
		addr.HasIPv6 = true
		return addr, nil
	case "samenet":
		addr.Special = "samenet"
		addr.Any = true
		return addr, nil
	}

	if strings.Contains(s, "/") {
		ip, ipnet, err := net.ParseCIDR(s)
		if err != nil || ip == nil || ipnet == nil {
			return addr, fmt.Errorf("invalid cidr: %s", token)
		}
		ipnet.IP = ip
		addr.Networks = []*net.IPNet{ipnet}
		addr.HasIPv4 = ip.To4() != nil
		addr.HasIPv6 = ip.To4() == nil
		return addr, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return addr, fmt.Errorf("invalid ip: %s", token)
	}
	if ip.To4() != nil {
		ipnet := mustCIDR(ip.String() + "/32")
		addr.Networks = []*net.IPNet{ipnet}
		addr.HasIPv4 = true
		return addr, nil
	}
	ipnet := mustCIDR(ip.String() + "/128")
	addr.Networks = []*net.IPNet{ipnet}
	addr.HasIPv6 = true
	return addr, nil
}

func mustCIDR(cidr string) *net.IPNet {
	ip, ipnet, _ := net.ParseCIDR(cidr)
	ipnet.IP = ip
	return ipnet
}

// IsLoopbackOnly проверяет, ограничены ли адреса лупбеком (127.0.0.0/8 или ::1).
func (a AddrSet) IsLoopbackOnly() bool {
	if a.Any {
		return false
	}
	if len(a.Networks) == 0 {
		return false
	}
	loop4 := mustCIDR("127.0.0.0/8")
	loop6 := mustCIDR("::1/128")
	for _, n := range a.Networks {
		if n.IP.To4() != nil {
			if !cidrContains(loop4, n) {
				return false
			}
			continue
		}
		if !cidrContains(loop6, n) {
			return false
		}
	}
	return true
}

// IsWideWith определяет «слишком широкие» диапазоны по порогам для IPv4/IPv6.
func (a AddrSet) IsWideWith(v4Prefix, v6Prefix int) bool {
	if a.Any {
		return true
	}
	for _, n := range a.Networks {
		ones, _ := n.Mask.Size()
		if n.IP.To4() != nil {
			if ones <= v4Prefix {
				return true
			}
		} else {
			if ones <= v6Prefix {
				return true
			}
		}
	}
	return false
}

// Covers проверяет, полностью ли адреса A покрывают адреса B (superset).
func (a AddrSet) Covers(b AddrSet) bool {
	if a.Any {
		return true
	}
	if b.Any {
		return false
	}
	if len(b.Networks) == 0 {
		return false
	}
	for _, bn := range b.Networks {
		covered := false
		for _, an := range a.Networks {
			if sameFamily(an, bn) && cidrContains(an, bn) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// Intersects проверяет, пересекаются ли диапазоны адресов.
func (a AddrSet) Intersects(b AddrSet) bool {
	if a.Any || b.Any {
		return true
	}
	for _, an := range a.Networks {
		for _, bn := range b.Networks {
			if sameFamily(an, bn) && cidrOverlaps(an, bn) {
				return true
			}
		}
	}
	return false
}

func sameFamily(a, b *net.IPNet) bool {
	return (a.IP.To4() != nil) == (b.IP.To4() != nil)
}

func cidrContains(a, b *net.IPNet) bool {
	// true, если сеть a полностью покрывает сеть b
	if !a.Contains(b.IP) {
		return false
	}
	aOnes, _ := a.Mask.Size()
	bOnes, _ := b.Mask.Size()
	return aOnes <= bOnes
}

func cidrOverlaps(a, b *net.IPNet) bool {
	// простая проверка пересечения сетей: начало одной лежит в другой
	return a.Contains(b.IP) || b.Contains(a.IP)
}
