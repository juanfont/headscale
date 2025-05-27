package state

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	hsdb "github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/derp"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/routes"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/sasha-s/go-deadlock"
	"tailscale.com/tailcfg"
	zcache "zgo.at/zcache/v2"
)

const (
	registerCacheExpiration = time.Minute * 15
	registerCacheCleanup    = time.Minute * 20
)

type State struct {
	mu  deadlock.RWMutex
	cfg *types.Config

	// in-memory data, protected by mu
	nodes types.Nodes
	users types.Users

	// subsystem keeping state
	db                *hsdb.HSDatabase
	ipAlloc           *hsdb.IPAllocator
	derpMap           *tailcfg.DERPMap
	polMan            policy.PolicyManager
	registrationCache *zcache.Cache[types.RegistrationID, types.RegisterNode]
	primaryRoutes     *routes.PrimaryRoutes
}

func NewState(cfg *types.Config) (*State, error) {
	registrationCache := zcache.New[types.RegistrationID, types.RegisterNode](
		registerCacheExpiration,
		registerCacheCleanup,
	)

	db, err := hsdb.NewHeadscaleDatabase(
		cfg.Database,
		cfg.BaseDomain,
		registrationCache,
	)
	if err != nil {
		return nil, fmt.Errorf("init database: %w", err)
	}

	ipAlloc, err := hsdb.NewIPAllocator(db, cfg.PrefixV4, cfg.PrefixV6, cfg.IPAllocation)
	if err != nil {
		return nil, fmt.Errorf("init ip allocatior: %w", err)
	}

	derpMap := derp.GetDERPMap(cfg.DERP)

	nodes, err := db.ListNodes()
	if err != nil {
		return nil, fmt.Errorf("loading nodes: %w", err)
	}
	users, err := db.ListUsers()
	if err != nil {
		return nil, fmt.Errorf("loading users: %w", err)
	}

	pol, err := policyBytes(db, cfg)
	if err != nil {
		return nil, fmt.Errorf("loading policy: %w", err)
	}

	polMan, err := policy.NewPolicyManager(pol, users, nodes)
	if err != nil {
		return nil, fmt.Errorf("init policy manager: %w", err)
	}

	return &State{
		cfg: cfg,

		nodes: nodes,
		users: users,

		db:      db,
		ipAlloc: ipAlloc,
		// TODO(kradalby): Update DERPMap
		derpMap:           derpMap,
		polMan:            polMan,
		registrationCache: registrationCache,
		primaryRoutes:     routes.New(),
	}, nil
}

func policyBytes(db *hsdb.HSDatabase, cfg *types.Config) ([]byte, error) {
	switch cfg.Policy.Mode {
	case types.PolicyModeFile:
		path := cfg.Policy.Path

		// It is fine to start headscale without a policy file.
		if len(path) == 0 {
			return nil, nil
		}

		absPath := util.AbsolutePathFromConfigPath(path)
		policyFile, err := os.Open(absPath)
		if err != nil {
			return nil, err
		}
		defer policyFile.Close()

		return io.ReadAll(policyFile)

	case types.PolicyModeDB:
		p, err := db.GetPolicy()
		if err != nil {
			if errors.Is(err, types.ErrPolicyNotFound) {
				return nil, nil
			}

			return nil, err
		}

		if p.Data == "" {
			return nil, nil
		}

		return []byte(p.Data), err
	}

	return nil, fmt.Errorf("unsupported policy mode: %s", cfg.Policy.Mode)
}

func (s *State) DERPMap() *tailcfg.DERPMap {
	return s.derpMap
}

func (s *State) ValidateAPIKey(key string) (bool, error) {
	return s.db.ValidateAPIKey(key)
}
