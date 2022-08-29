package org.jitsi.impl.neomedia.transform.fec;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import javax.media.Buffer;
import org.jitsi.service.neomedia.RawPacket;
import org.jitsi.util.Logger;
import org.jitsi.util.RTPUtils;
import sdk.zorro.xfec.ReedSolomon;

public class RsFecReceiver extends AbstractFECReceiver {
  private static final Logger logger = Logger.getLogger(RsFecReceiver.class);

  static final boolean CHECK_MODE = System.getenv("RS_FEC_CHECK") != null;

  /** The max value of sequence number (exclusive) */
  static final int MAX_SEQ = 65536;

  /** Max number of reconstructors allowed at the same time */
  static final int MAX_RECONSTRUCTORS = 3;

  /** The RS-FEC header length */
  static final int RS_FEC_HEADER_LENGTH = 8;

  /** The minimum overhead of the RS-FEC packet */
  static final int RS_FEC_MIN_OVERHEAD = 10;

  /** Max number of source packets that can be protected */
  static final int MAX_SOURCE_PACKETS = 48;

  /** The packet reconstructors */
  private final TreeMap<Integer, Reconstructor> mReconstructors = new TreeMap<>(sequenceNumberComparator);

  /**
   * Initialize the FEC receiver
   *
   * @param ssrc the ssrc of the stream on which fec packets will be received
   * @param payloadType the payload type of the fec packets
   */
  RsFecReceiver(long ssrc, byte payloadType) {
    super(ssrc, payloadType);
  }

  @Override
  protected RawPacket[] doReverseTransform(RawPacket[] packets) {
    for (RawPacket packet : fecPackets.values()) {
      int payloadLength = packet.getPayloadLength();
      if (payloadLength < RS_FEC_MIN_OVERHEAD) {
        logger.error(String.format("FEC packet too small: length=%d", payloadLength));
        continue;
      }
      //     0                   1                   2                   3
      //    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      //   |      Enc. Symbol ID (ESI)     |            SN_base            |
      //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      //   |    Source Block Length (k)    |              n_r              |
      //   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      //
      // read the RS-FEC header

      int esi = RTPUtils.readUint16AsInt(packet.getBuffer(), packet.getHeaderLength());
      int snBase = RTPUtils.readUint16AsInt(packet.getBuffer(), packet.getHeaderLength() + 2);
      int sourceSymbols =
          RTPUtils.readUint16AsInt(packet.getBuffer(), packet.getHeaderLength() + 4);
      int repairSymbols =
          RTPUtils.readUint16AsInt(packet.getBuffer(), packet.getHeaderLength() + 6);
      if (esi >= sourceSymbols + repairSymbols || esi < sourceSymbols) {
        logger.error(
            String.format(
                "Invalid esi (%d) value, sources=%d repairs=%d",
                esi, sourceSymbols, repairSymbols));
        continue;
      }
      if (sourceSymbols > MAX_SOURCE_PACKETS) {
        logger.error("The number of source packets (" + sourceSymbols + ") is too large");
      }
      if (repairSymbols > sourceSymbols) {
        logger.error(
            String.format(
                "The repair packets (%d) must be less than the source packets (%d)",
                repairSymbols, sourceSymbols));
      }
      // create a new reconstructor if not exists
      Reconstructor reconstructor = mReconstructors.get(snBase);
      if (reconstructor == null) {
        reconstructor = new Reconstructor(snBase, sourceSymbols, repairSymbols);
        mReconstructors.put(snBase, reconstructor);
      }
      // add the repair packet to the reconstructor
      reconstructor.addRepair(esi, packet);
    }
    fecPackets.clear();
    // add source packets to corresponding reconstructors
    for (Reconstructor reconstructor : mReconstructors.values()) {
      int from = reconstructor.firstSequence();
      int to = reconstructor.lastSequence();
      SortedMap<Integer, RawPacket> range = mediaPackets.subMap(from, to);
      for (Map.Entry<Integer, RawPacket> entry : range.entrySet()) {
        reconstructor.addSource(entry.getValue());
      }
      range.clear();
      // wraparound
      if (to >= MAX_SEQ) {
        range = mediaPackets.subMap(0, to - MAX_SEQ);
        for (Map.Entry<Integer, RawPacket> entry : range.entrySet()) {
          reconstructor.addSource(entry.getValue());
        }
        range.clear();
      }
    }
    List<RawPacket> recovered = new ArrayList<>();
    int toRemove = Math.max(mReconstructors.size(), MAX_RECONSTRUCTORS) - MAX_RECONSTRUCTORS;
    Iterator<Reconstructor> iterator = mReconstructors.values().iterator();
    while (iterator.hasNext()) {
      Reconstructor reconstructor = iterator.next();
      if (reconstructor.repairable()) {
        recovered.addAll(reconstructor.repair());
        // remove complete reconstructors
        iterator.remove();
      } else if (toRemove-- > 0) {
        // remove redundant reconstructors
        iterator.remove();
      }
    }
    // append the recovered packets to the packets list
    if (!recovered.isEmpty()) {
      RawPacket[] result = Arrays.copyOf(packets, packets.length + recovered.size());
      int index = packets.length;
      for (RawPacket packet : recovered) {
        result[index++] = packet;
      }
      return result;
    }
    return packets;
  }

  /** Used to reconstruct source packets using reed-solomon algorithm */
  class Reconstructor {

    /** The number of received source packets */
    private int mNumSourcePackets = 0;
    /** The number of received repair packets */
    private int mNumRepairPackets = 0;
    /**
     * The lowest RTP sequence number (taking wraparound into account) of the protected source
     * packets
     */
    private final int mSnBase;
    /** The number of protected source packets in the ADU block */
    private final int mSourceSymbols;
    /** The number of generated fec packets */
    private final int mRepairSymbols;
    /** The received source packets */
    private final RawPacket[] mSourcePackets;
    /** The received repair packets */
    private final RawPacket[] mRepairPackets;
    /** The packet checker */
    private final Checker mChecker = new Checker();

    /**
     * Initialize a new <tt>Reconstructor</tt> instance.
     *
     * @param snBase the lowest sequence number of the protected source packets
     * @param sourceSymbols the number of protected source packets
     * @param repairSymbols the number of generated fec packets
     */
    Reconstructor(int snBase, int sourceSymbols, int repairSymbols) {
      assert sourceSymbols > 0;
      assert repairSymbols > 0;
      assert snBase < MAX_SEQ;
      mSnBase = snBase;
      mSourceSymbols = sourceSymbols;
      mRepairSymbols = repairSymbols;
      mSourcePackets = new RawPacket[sourceSymbols];
      mRepairPackets = new RawPacket[repairSymbols];
    }

    /**
     * Get the first sequence of the source packets.
     *
     * @return the first sequence of the source packets
     */
    int firstSequence() {
      return mSnBase;
    }

    int lastSequence() {
      return mSnBase + mSourceSymbols;
    }

    /**
     * Add a repair packet
     *
     * @param esi the encoding-symbol-id of the packet
     * @param packet the repair packet
     */
    void addRepair(int esi, RawPacket packet) {
      int index = esi - mSourceSymbols;
      assert index > 0 && index < mRepairSymbols;
      if (mRepairPackets[index] == null) {
        ++mNumRepairPackets;
      }
      mRepairPackets[index] = packet;
    }

    /**
     * Add a source packet
     *
     * @param packet the source packet
     */
    void addSource(RawPacket packet) {
      int sequence = packet.getSequenceNumber();
      int index;
      if (sequence >= mSnBase) {
        if (sequence >= mSnBase + mSourceSymbols) {
          // out of range
          return;
        }
        index = sequence - mSnBase;
      } else {
        // wraparound sequence number
        if (mSnBase + mSourceSymbols <= MAX_SEQ || sequence + MAX_SEQ >= mSnBase + mSourceSymbols) {
          // out of range
          return;
        }
        index = MAX_SEQ + sequence - mSnBase;
      }
      if (mSourcePackets[index] == null) {
        ++mNumSourcePackets;
      }
      mSourcePackets[index] = packet;
    }

    /**
     * Check if the missing packets of this reconstructor can be repaired
     *
     * @return true if the missing packets of this reconstructor can be repaired
     */
    boolean repairable() {
      if (mChecker.enabled()) {
        return mNumSourcePackets == mSourceSymbols;
      }
      return mNumSourcePackets + mNumRepairPackets >= mSourceSymbols;
    }

    /**
     * Repair the missing packets
     *
     * @return a list of the missing packets, must not be null
     */
    List<RawPacket> repair() {
      assert repairable();
      LinkedList<RawPacket> result = new LinkedList<>();
      mChecker.prepare(this);
      // do nothing if the source packets is complete
      if (mNumSourcePackets == mSourceSymbols) {
        return result;
      }
      // calculate the symbol length
      int symbolLength = -1;
      for (RawPacket packet : mRepairPackets) {
        if (packet == null) {
          continue;
        }
        int payloadLength = packet.getPayloadLength();
        if (payloadLength < RS_FEC_MIN_OVERHEAD) {
          // an invalid fec packet received
          logger.error(String.format("Invalid RS-FEC packet, payload-length=%d", payloadLength));
          return result;
        }
        int currentSymbolLength = payloadLength - RS_FEC_HEADER_LENGTH;
        if (symbolLength == -1) {
          symbolLength = currentSymbolLength;
        } else if (symbolLength != currentSymbolLength) {
          // FEC packets in the same ADU block must have the same length
          logger.error(
              String.format(
                  "Mismatched symbol length, current=%d expected=%d",
                  currentSymbolLength, symbolLength));
          return result;
        }
      }
      byte[][] shards = new byte[mSourceSymbols + mRepairSymbols][];
      // save the indices of the missing source packets
      LinkedList<Integer> indices = new LinkedList<>();
      // generate the source block of each source packet
      for (int i = 0; i < mSourcePackets.length; ++i) {
        RawPacket packet = mSourcePackets[i];
        if (packet == null) {
          shards[i] = null;
          indices.add(i);
          continue;
        }
        int length = packet.getLength();
        if (symbolLength < length + 2) {
          logger.error(
              String.format(
                  "The source packet length (%d) must be at least two bytes less than the symbol"
                      + "length (%d)",
                  length, symbolLength));
          return result;
        }
        shards[i] = new byte[symbolLength];
        // the first two bytes contain the length of the source packet
        RTPUtils.writeShort(shards[i], 0, (short) length);
        // then append the entire RTP packet (including its RTP header)
        System.arraycopy(packet.getBuffer(), 0, shards[i], 2, length);
        // then zero padding is added to the remaining bytes
      }
      // add the repair packets
      for (int i = 0; i < mRepairPackets.length; ++i) {
        RawPacket packet = mRepairPackets[i];
        if (packet != null) {
          shards[mSourceSymbols + i] =
              Arrays.copyOfRange(
                  packet.getPayload(), RS_FEC_HEADER_LENGTH, RS_FEC_HEADER_LENGTH + symbolLength);
        } else {
          shards[mSourceSymbols + i] = null;
        }
      }
      try {
        ReedSolomon.decode(mSourceSymbols, mRepairSymbols, symbolLength, shards);
      } catch (IOException e) {
        ++statistics.failedRecoveries;
        logger.error(String.format("Failed to decode RS-FEC, error=%s", e.getMessage()));
        return result;
      }
      // read the missing packets
      for (int index : indices) {
        byte[] shard = shards[index];
        if (shard == null) {
          logger.error("The generated missing packet is null");
          continue;
        }
        if (shard.length != symbolLength || shard.length < 2) {
          logger.error(
              String.format(
                  "Bad length of the reconstructed packet: length=%d expected=%d",
                  shard.length, symbolLength));
          continue;
        }
        int length = RTPUtils.readUint16AsInt(shard, 0);
        if (shard.length < length + 2) {
          logger.error(
              String.format("Invalid ADU length: read=%d length=%d", length, shard.length));
          continue;
        }
        if (!mChecker.checkPadding(shard, length + 2, shard.length)) {
          logger.error(
              String.format(
                  "Invalid padding: %s",
                  Arrays.toString(Arrays.copyOfRange(shard, length + 2, shard.length))));
        }
        RawPacket packet = new RawPacket(shards[index], 2, length);
        packet.setFlags(Buffer.FLAG_REPAIR | packet.getFlags());
        mChecker.validate(packet);
        ++statistics.numRecoveredPackets;
        result.add(packet);
      }
      return result;
    }
  }

  static class Checker {
    RawPacket origin = null;

    boolean enabled() {
      return CHECK_MODE;
    }

    void prepare(Reconstructor reconstructor) {
      if (!CHECK_MODE || reconstructor.mNumRepairPackets == 0) {
        return;
      }
      if (reconstructor.mNumRepairPackets + reconstructor.mNumSourcePackets
          <= reconstructor.mSourceSymbols) {
        return;
      }
      int index = (int) (System.nanoTime() % reconstructor.mSourceSymbols);
      assert reconstructor.mSourcePackets[index] != null;
      origin = reconstructor.mSourcePackets[index];
      if (origin != null) {
        reconstructor.mSourcePackets[index] = null;
        --reconstructor.mNumSourcePackets;
      }
    }

    void validate(RawPacket recovered) {
      if (origin == null || recovered == null) {
        return;
      }
      if (recovered.getSequenceNumber() != origin.getSequenceNumber()) {
        return;
      }
      byte[] originBuffer =
          Arrays.copyOfRange(
              origin.getBuffer(), origin.getOffset(), origin.getLength() + origin.getOffset());
      byte[] recoveredBuffer =
          Arrays.copyOfRange(
              recovered.getBuffer(),
              recovered.getOffset(),
              recovered.getLength() + recovered.getOffset());
      if (!Arrays.equals(originBuffer, recoveredBuffer)) {
        logger.error(
            String.format(
                "Error recovering packet: origin=[%d][%s] recovered=[%d][%s]",
                originBuffer.length,
                Arrays.toString(originBuffer),
                recoveredBuffer.length,
                Arrays.toString(recoveredBuffer)));
      }
    }

    boolean checkPadding(byte[] data, int from, int to) {
      for (int i = from; i < to; ++i) {
        if (data[i] != 0) {
          return false;
        }
      }
      return true;
    }
  }
}
