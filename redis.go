package outback

import (
	log "github.com/Sirupsen/logrus"
	"github.com/go-redis/redis"
)

func (oa *OutbackApp) getRedis() (*redis.Client, error) {
	if oa.redis != nil {

		err := oa.redis.Ping().Err()
		if err != nil {
			log.WithError(err).Error("Redis connection failed testing, destroying and reconnecting")
			defer oa.redis.Close()
			oa.redis = nil
			return oa.getRedis()
		}

		return oa.redis, nil
	}
	oa.redis = redis.NewClient(&redis.Options{
		Addr:     oa.Config.RedisURI,
		Password: "",
		DB:       0,
	})
	return oa.redis, oa.redis.Ping().Err()
}
