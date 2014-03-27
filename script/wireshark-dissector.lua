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

			local cmd = buffer(28, 4)
			local tcmd = T32(hdr, cmd, 0,    "Cmd     %08x, \"" .. cmd:string() .. "\"");

			local from = buffer(20, 4)
			local tfrom = T32(hdr, from, 0,  "From    %08x");
			if bit.band(from:uint(), 0x80000000) > 0 then
				tfrom:add_expert_info(PI_PROTOCOL,  PI_WARN, "Highest bit set")
			end

			local len = buffer(24, 4)
			local tlen = T32(hdr, len, 0,    "Length  %8d");
			if len:uint() > 1000 then
				tlen:add_expert_info(PI_PROTOCOL,  PI_WARN, "Length too big?")
			end

			T32(hdr, buffer, 32,             "Result  %08x");
			T32(hdr, buffer, 12,             "Magic   %08x");
			T32(hdr, buffer, 16,             "Version %08x");

			T32(hdr, buffer,  0,             "IV      %08x");
			T32(hdr, buffer,  4,             "Auth1   %08x");
			T32(hdr, buffer,  8,             "Auth2   %08x");



			if (endbuf > 36) then
				local tick = tree:add(booth_proto, buffer(36, endbuf-36), "Booth data")
				local name = buffer(36, 64)
				tick:add(name,                "Ticket name: ", name:string())

				T32(tick, buffer, 36+64 +  0, "Leader:         %08x")
				T32(tick, buffer, 36+64 +  4, "Term:           %08x")
				T32(tick, buffer, 36+64 +  8, "Term valid for: %08x")
				T32(tick, buffer, 36+64 + 12, "Leader commit:  %8d")
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

