<?php
namespace PolarBear\Tool;

//redis 分布式和单点式锁
class RedLock
{
    private $retryDelay;
    private $retryCount;
    private $clockDriftFactor = 0.01;
    private $quorum;
    private $servers = array();
    private $instances = array();

    //如果不重试，retryDelay和retryCount可传递0，如果是单点redis，servers传递一个就ok
    function __construct(array $servers, $retryDelay = 200, $retryCount = 3)
    {
        $this->servers = $servers;
        $this->retryDelay = $retryDelay;
        $this->retryCount = $retryCount;
        $this->quorum = min(count($servers), (count($servers) / 2 + 1));
    }

    public function lock($resource, $ttl, $token = '')
    {
        $this->initInstances();
        $token = empty($token) ? uniqid() : $token; //默认为空，如果不为空，则用传递的值
        $retry = $this->retryCount;
        do {
            $n = 0;
            $startTime = microtime(true) * 1000;
            foreach ($this->instances as $instance) {
                if ($this->lockInstance($instance, $resource, $token, $ttl)) {
                    $n++;
                }
            }
            # Add 2 milliseconds to the drift to account for Redis expires
            # precision, which is 1 millisecond, plus 1 millisecond min drift
            # for small TTLs.
            $drift = ($ttl * $this->clockDriftFactor) + 2;
            $validityTime = $ttl - (microtime(true) * 1000 - $startTime) - $drift;
            if ($n >= $this->quorum && $validityTime > 0) {
                return [
                    'validity' => $validityTime,
                    'resource' => $resource,
                    'token' => $token,
                ];
            } else {
                foreach ($this->instances as $instance) {
                    $this->unlockInstance($instance, $resource, $token);
                }
            }
            // Wait a random delay before to retry
            $delay = mt_rand(floor($this->retryDelay / 2), $this->retryDelay);
            usleep($delay * 1000);
            $retry--;
        } while ($retry > 0);
        return false;
    }

    public function unlock(array $lock)
    {
        $this->initInstances();
        $resource = $lock['resource'];
        $token = $lock['token'];
        foreach ($this->instances as $instance) {
            $this->unlockInstance($instance, $resource, $token);
        }
    }

    private function initInstances()
    {
        if (empty($this->instances)) {
            foreach ($this->servers as $server) {
                list($host, $port, $timeout) = $server;
                $redis = new \Redis();
                $redis->connect($host, $port, $timeout);
                $this->instances[] = $redis;
            }
        }
    }

    private function lockInstance($instance, $resource, $token, $ttl)
    {
        return $instance->set($resource, $token, ['NX', 'PX' => $ttl]);
    }

    private function unlockInstance($instance, $resource, $token)
    {
        $script = '
            if redis.call("GET", KEYS[1]) == ARGV[1] then
                return redis.call("DEL", KEYS[1])
            else
                return 0
            end
        ';
        return $instance->eval($script, [$resource, $token], 1);
    }
}
