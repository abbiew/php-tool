<?php

namespace Swoole\Coroutine;

use Swoole\Coroutine;

class BaseContext
{
    protected static $pool = [];

    static function get($type)
    {
        $cid = Coroutine::getuid();
        if ($cid < 0)
        {
            return false;
        }
        if (isset(self::$pool[$type][$cid])){
            return self::$pool[$type][$cid];
        }
        return false;
    }

    static function put($type, $object)
    {
        $cid = Coroutine::getuid();
        if ($cid < 0)
        {
            return;
        }
        self::$pool[$type][$cid] = $object;
    }

    static function delete($type)
    {
        $cid = Coroutine::getuid();
        if ($cid < 0)
        {
            return;
        }
        unset(self::$pool[$type][$cid]);
    }
}