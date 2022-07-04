package com.tsystems.gematik.komle.clientmodule.av.clamav;

import static io.netty.channel.ChannelOption.CONNECT_TIMEOUT_MILLIS;
import static java.nio.charset.StandardCharsets.US_ASCII;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.tsystems.gematik.komle.clientmodule.av.AntiVirusEngine;
import com.tsystems.gematik.komle.clientmodule.av.AntiVirusEngineException;
import com.tsystems.gematik.komle.clientmodule.av.AntiVirusEngineVirusFoundException;
import com.tsystems.gematik.komle.mail.util.Util;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.PooledByteBufAllocator;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;

public class ClamAVEngine implements AntiVirusEngine {

	private final Logger log = LogManager.getLogger(ClamAVEngine.class);

	private static byte[] CLAMAV_EOF = new byte[] { 0, 0, 0, 0 };

	private EventLoopGroup group = new NioEventLoopGroup();

	private Bootstrap bootstrap = new Bootstrap();

	private Channel channel;

	private BlockingQueue<String> replies = new LinkedBlockingQueue<String>();

	private long readTimeoutInSec = 1;

	public ClamAVEngine() throws AntiVirusEngineException {
		this(null, 0);
	}

	public ClamAVEngine(String hostname, int port) throws AntiVirusEngineException {
		try {
			if (hostname == null)
				hostname = "localhost";
			if (port == 0)
				port = 3310;

			this.bootstrap.group(group).channel(NioSocketChannel.class)
					.remoteAddress(new InetSocketAddress(hostname, port)).option(CONNECT_TIMEOUT_MILLIS, 1000)
					.handler(new ChannelInitializer<SocketChannel>() {
						protected void initChannel(SocketChannel socketChannel) throws Exception {
							socketChannel.pipeline().addLast(new ClamAVHandler());
						}
					});
			this.channel = bootstrap.connect().sync().channel();
		} catch (Exception e) {
			throw new AntiVirusEngineException(e);
		}
	}

	@Override
	public void scan(String contentLabel, ByteBuffer bb)
			throws AntiVirusEngineException, AntiVirusEngineVirusFoundException {
		try {
			ByteBuf buffer = PooledByteBufAllocator.DEFAULT.buffer(bb.capacity());
			buffer.writeCharSequence("zINSTREAM\0", US_ASCII);
			buffer.writeInt(bb.capacity());
			buffer.writeBytes(bb);
			buffer.writeBytes(CLAMAV_EOF);
			this.channel.writeAndFlush(buffer).syncUninterruptibly();

			String reply = replies.poll(this.readTimeoutInSec, TimeUnit.SECONDS);

			if (reply.contains("OK")) {
				log.info("No virus found.");
			} else if (reply.contains("FOUND")) {
				log.error("Virus found: {}", reply);
				throw new AntiVirusEngineVirusFoundException(reply);
			} else {
				throw new AntiVirusEngineException("non expected result: ', " + reply);
			}
		} catch (InterruptedException e) {
			throw new AntiVirusEngineException(e);
		}
	}

	public void ping() throws AntiVirusEngineException {
		try {
			this.channel.writeAndFlush(Util.toByteBuf("zPING\0")).syncUninterruptibly();
			String reply = replies.poll(this.readTimeoutInSec, TimeUnit.SECONDS);
			if (reply.equals("PONG")) {
				log.info("ClamAV is available.");
			} else {
				throw new AntiVirusEngineException("non expected result: ', " + reply);
			}
		} catch (Exception e) {
			log.catching(e);
			throw new AntiVirusEngineException(e);
		}
	}

	@Override
	public void close() throws IOException {
		this.channel.close().syncUninterruptibly();
		this.group.shutdownGracefully().syncUninterruptibly();
	}

	private class ClamAVHandler extends SimpleChannelInboundHandler {

		@Override
		public void channelRead0(ChannelHandlerContext ctx, Object msg) throws Exception {
			ByteBuf frame = (ByteBuf) msg;
			String strFrame = frame.readCharSequence(frame.readableBytes(), US_ASCII).toString().trim();

			log.trace("Received clamav client frame: {}", strFrame);

			replies.add(strFrame);
		}

		@Override
		public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
			log.catching(cause);
			ctx.close();
		}
	}

}
