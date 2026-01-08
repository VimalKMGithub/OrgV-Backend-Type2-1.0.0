package org.v.commons.utils;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ZSetOperations;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class RedisServiceUtility {
    private static final Duration DEFAULT_TTL = Duration.ofMinutes(5);

    public static void redisSave(String key,
                                 String value,
                                 StringRedisTemplate stringRedisTemplate) {
        redisSave(key, value, DEFAULT_TTL, stringRedisTemplate);
    }

    public static void redisSave(String key,
                                 String value,
                                 Duration timeToLive,
                                 StringRedisTemplate stringRedisTemplate) {
        stringRedisTemplate.opsForValue().set(key, value, timeToLive);
    }

    public static String redisGet(String key,
                                  StringRedisTemplate stringRedisTemplate) {
        return stringRedisTemplate.opsForValue().get(key);
    }

    public static List<String> redisGetAll(Set<String> keys,
                                           StringRedisTemplate stringRedisTemplate) {
        return stringRedisTemplate.opsForValue().multiGet(keys);
    }

    public static void redisDelete(String key,
                                   StringRedisTemplate stringRedisTemplate) {
        stringRedisTemplate.delete(key);
    }

    public static void redisDeleteAll(Set<String> keys,
                                      StringRedisTemplate stringRedisTemplate) {
        stringRedisTemplate.delete(keys);
    }

    public static Boolean redisAddZSetMember(String key,
                                             String member,
                                             double score,
                                             Duration timeToLive,
                                             StringRedisTemplate stringRedisTemplate) {
        Boolean isAdded = stringRedisTemplate.opsForZSet().add(key, member, score);
        stringRedisTemplate.expire(key, timeToLive);
        return isAdded;
    }

    public static Set<String> redisGetAllZSetMembers(String key,
                                                     StringRedisTemplate stringRedisTemplate) {
        return stringRedisTemplate.opsForZSet().range(key, 0, -1);
    }

    public static void redisRemoveZSetMember(String key,
                                             String member,
                                             StringRedisTemplate stringRedisTemplate) {
        stringRedisTemplate.opsForZSet().remove(key, member);
    }

    public static void redisRemoveZSetMembers(String key,
                                              Object[] members,
                                              StringRedisTemplate stringRedisTemplate) {
        stringRedisTemplate.opsForZSet().remove(key, members);
    }

    public static Set<ZSetOperations.TypedTuple<String>> redisPopNMinZSetMembers(String key,
                                                                                 long count,
                                                                                 StringRedisTemplate stringRedisTemplate) {
        return stringRedisTemplate.opsForZSet().popMin(key, count);
    }

    public static Long redisGetZSetSize(String key,
                                        StringRedisTemplate stringRedisTemplate) {
        return stringRedisTemplate.opsForZSet().size(key);
    }

    public static void redisAddHashMember(String key,
                                          String member,
                                          String value,
                                          Duration timeToLive,
                                          StringRedisTemplate stringRedisTemplate) {
        stringRedisTemplate.opsForHash().put(key, member, value);
        stringRedisTemplate.opsForHash().expire(key, timeToLive, Set.of(member));
    }

    public static void redisRemoveHashMember(String key,
                                             String member,
                                             StringRedisTemplate stringRedisTemplate) {
        stringRedisTemplate.opsForHash().delete(key, member);
    }

    public static void redisRemoveHashMembers(String key,
                                              Object[] members,
                                              StringRedisTemplate stringRedisTemplate) {
        stringRedisTemplate.opsForHash().delete(key, members);
    }

    public static Object redisGetHashMember(String key,
                                            String member,
                                            StringRedisTemplate stringRedisTemplate) {
        return stringRedisTemplate.opsForHash().get(key, member);
    }

    public static Map<Object, Object> redisGetAllHashMembers(String key,
                                                             StringRedisTemplate stringRedisTemplate) {
        return stringRedisTemplate.opsForHash().entries(key);
    }

    public static void redisFlushDb(StringRedisTemplate stringRedisTemplate) {
        Objects.requireNonNull(stringRedisTemplate.getConnectionFactory())
                .getConnection()
                .serverCommands()
                .flushDb();
    }
}
