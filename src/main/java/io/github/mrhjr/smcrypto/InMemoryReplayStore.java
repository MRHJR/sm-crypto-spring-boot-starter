package io.github.mrhjr.smcrypto;

import java.util.Comparator;
import java.util.HashSet;
import java.util.PriorityQueue;
import java.util.Set;

final class InMemoryReplayStore implements ReplayStore {
    private final int capacity;
    private final Set<String> ids = new HashSet<>();
    private final PriorityQueue<Entry> expiryOrder = new PriorityQueue<>(Comparator.comparingLong(e -> e.expiry));

    InMemoryReplayStore(int capacity) {
        if (capacity < 1 || capacity > 1_000_000) {
            throw new IllegalArgumentException("sm-crypto.replay-capacity must be between 1 and 1000000");
        }
        this.capacity = capacity;
    }

    @Override
    public synchronized boolean claim(String id, long expiresAt, long now) {
        while (!expiryOrder.isEmpty() && expiryOrder.peek().expiry < now) {
            ids.remove(expiryOrder.remove().id);
        }
        if (expiresAt < now || ids.size() >= capacity || !ids.add(id)) {
            return false;
        }
        expiryOrder.add(new Entry(id, expiresAt));
        return true;
    }

    private static final class Entry {
        final String id;
        final long expiry;
        Entry(String id, long expiry) { this.id = id; this.expiry = expiry; }
    }
}
