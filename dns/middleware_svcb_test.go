package dns

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
	icontext "github.com/metacubex/mihomo/context"

	D "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testSvcbAlpn = map[string][]string{
	"+.twimg.com":       {"h3", "h2"},
	"video.example.com": {"h3"},
}

func newTestSvcbTrie(t *testing.T) *trie.DomainTrie[[]string] {
	t.Helper()
	svcb := trie.New[[]string]()
	for domain, alpn := range testSvcbAlpn {
		require.NoError(t, svcb.Insert(domain, alpn))
	}
	return svcb
}

func TestLookupSVCBAlpn(t *testing.T) {
	svcb := newTestSvcbTrie(t)

	alpn, ok := lookupSVCBAlpn(svcb, "video.twimg.com")
	assert.True(t, ok)
	assert.Equal(t, []string{"h3", "h2"}, alpn)

	// "+." 前缀在 mihomo 的 trie 里同时覆盖裸域与子域
	_, ok = lookupSVCBAlpn(svcb, "twimg.com")
	assert.True(t, ok)

	_, ok = lookupSVCBAlpn(svcb, "video.example.com")
	assert.True(t, ok)

	_, ok = lookupSVCBAlpn(svcb, "www.example.com")
	assert.False(t, ok)

	_, ok = lookupSVCBAlpn(nil, "video.twimg.com")
	assert.False(t, ok)
}

func TestBuildSVCBMsg(t *testing.T) {
	for _, qtype := range []uint16{D.TypeHTTPS, D.TypeSVCB} {
		q := new(D.Msg)
		q.SetQuestion("video.twimg.com.", qtype)
		q.Id = 1234

		msg := buildSVCBMsg(q, q.Question[0], []string{"h3", "h2"})

		require.Len(t, msg.Answer, 1)
		rr := msg.Answer[0]
		assert.Equal(t, qtype, rr.Header().Rrtype)
		assert.Equal(t, "video.twimg.com.", rr.Header().Name)
		assert.Equal(t, uint32(svcbAnswerTTL), rr.Header().Ttl)
		assert.Equal(t, uint16(1234), msg.Id)

		var svcb *D.SVCB
		switch v := rr.(type) {
		case *D.HTTPS:
			svcb = &v.SVCB
		case *D.SVCB:
			svcb = v
		default:
			t.Fatalf("unexpected answer type %T", rr)
		}

		// Target "." 表示服务就在域名本身；不带 hint，避免客户端绕开 fake-ip 映射
		assert.Equal(t, ".", svcb.Target)
		assert.Equal(t, uint16(1), svcb.Priority)
		require.Len(t, svcb.Value, 1)
		alpn, ok := svcb.Value[0].(*D.SVCBAlpn)
		require.True(t, ok)
		assert.Equal(t, []string{"h3", "h2"}, alpn.Alpn)
	}
}

func TestWithFakeIPSvcb(t *testing.T) {
	pool, err := fakeip.New(fakeip.Options{
		IPNet: netip.MustParsePrefix("198.18.0.1/16"),
		Size:  1000,
	})
	require.NoError(t, err)

	newQuery := func(host string, qtype uint16) *D.Msg {
		q := new(D.Msg)
		q.SetQuestion(D.Fqdn(host), qtype)
		return q
	}
	upstream := func(_ *icontext.DNSContext, _ *D.Msg) (*D.Msg, error) {
		t.Fatal("synth record should not reach upstream resolver")
		return nil, nil
	}

	h := withFakeIP(&fakeip.Skipper{Mode: C.FilterBlackList}, pool, nil, 1, newTestSvcbTrie(t))(upstream)

	for _, qtype := range []uint16{D.TypeHTTPS, D.TypeSVCB} {
		resp, err := h(&icontext.DNSContext{}, newQuery("video.twimg.com", qtype))
		require.NoError(t, err)
		require.Len(t, resp.Answer, 1)
		assert.Equal(t, qtype, resp.Answer[0].Header().Rrtype)
	}

	// 未命中的域名仍返回空答案（浏览器据此继续走 h2）
	resp, err := h(&icontext.DNSContext{}, newQuery("unknown.example.org", D.TypeHTTPS))
	require.NoError(t, err)
	assert.Empty(t, resp.Answer)
}
