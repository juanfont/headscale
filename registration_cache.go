package headscale

import (
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/log"
	"tailscale.com/types/key"
)

const (
	registerCacheExpiration = time.Minute * 15
)

type registrationCache struct {
	innerCache *cache.Cache
}

func newRegistrationCache() *registrationCache {
	cache := cache.New(
		registerCacheExpiration,
		registerCacheCleanup,
	)
	return &registrationCache{
		innerCache: cache,
	}
}

func (rc *registrationCache) encodeKey(key key.NodePublic) string {
	return NodePublicKeyStripPrefix(key)
}

func (rc *registrationCache) Set(key key.NodePublic, machine Machine) {
	log.Debug().
		Str("key", key.String()).
		Msg("new machine is registered in to cache")
	rc.innerCache.Set(
		rc.encodeKey(key),
		machine,
		registerCacheExpiration,
	)
}

func (rc *registrationCache) Get(key key.NodePublic) (Machine, bool) {
	_m, ok := rc.innerCache.Get(rc.encodeKey(key))
	if ok {
		return _m.(Machine), ok
	}
	return Machine{}, false
}

func (rc *registrationCache) Delete(key key.NodePublic) {
	rc.innerCache.Delete(rc.encodeKey(key))
}
