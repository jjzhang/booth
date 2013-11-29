-- dofile("wireshark-dissector.lua")
--
do
	booth_proto = Proto("Booth","Booth")

	function T32(tree, buffer, start, format)
		local b = buffer(start, 4)
		return tree:add(b, string.format(format, b:uint()))
	end

	function booth_proto.dissector(buffer, pinfo, tree)
		local endbuf = buffer:len()
		pinfo.cols.protocol = "Booth"

		if (endbuf < 24) then
			pinfo.cols.info = "Booth - too small"
		else
			local hdr = tree:add(booth_proto, buffer(0, 24), "Booth header")

			local cmd = buffer(16, 4)
			local tcmd = T32(hdr, cmd, 0,    "Cmd     %08x, \"" .. cmd:string() .. "\"");

			local from = buffer(8, 4)
			local tfrom = T32(hdr, from, 0,  "From    %08x");
			if bit.band(from:uint(), 0x80000000) > 0 then
				tfrom:add_expert_info(PI_PROTOCOL,  PI_WARN, "Highest bit set")
			end

			local len = buffer(12, 4)
			local tlen = T32(hdr, len, 0,    "Length  %8d");
			if len:uint() > 1000 then
				tlen:add_expert_info(PI_PROTOCOL,  PI_WARN, "Length too big?")
			end

			T32(hdr, buffer, 20,             "Result  %08x");
			T32(hdr, buffer,  0,             "Magic   %08x");
			T32(hdr, buffer,  4,             "Version %08x");



			if (endbuf > 24) then
				local tick = tree:add(booth_proto, buffer(24, endbuf-24), "Booth data")
				local name = buffer(24, 64)
				tick:add(name,                "Ticket name: ", name:string())

				T32(tick, buffer, 24+64 +  0, "Owner:        %08x")
				T32(tick, buffer, 24+64 +  4, "Ballot:       %08x")
				T32(tick, buffer, 24+64 +  8, "Prev. Ballot: %08x")
				T32(tick, buffer, 24+64 + 12, "Expiry:       %8d")
			end

			pinfo.cols.info = "Booth, cmd " .. cmd:string()
		end
		tree:add(booth_proto, buffer(0, endbuf), "data")
	end

	local tbl = DissectorTable.get("udp.port")
	tbl:add(9929, booth_proto)

	local tbl = DissectorTable.get("tcp.port")
	tbl:add(9929, booth_proto)
end

