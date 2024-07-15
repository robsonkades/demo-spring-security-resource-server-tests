package com.robsonkades.security;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCacheManager;

import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
public class JwtDecoderServiceBenchmark {

    private JwtDecoderService jwtDecoderService;
    private String issuer;

    @Setup(Level.Trial)
    public void setUp() {
        CacheManager cacheManager = new CaffeineCacheManager();
        jwtDecoderService = new JwtDecoderService(cacheManager);
        issuer = "http://example.com";
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Warmup(iterations = 5)
    @Fork(value = 5)
    public void testGetJwtDecoder() {
        jwtDecoderService.getJwtDecoder(issuer);
    }

    public static void main(String[] args) throws Exception {
        org.openjdk.jmh.Main.main(args);
    }
}
