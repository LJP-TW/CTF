module check(
    input clk,

    input [6:0] data,
    output wire open_safe,
    output wire [55:0] my_test,
    output wire [55:0] my_test2,
    output wire [6:0]  my_memory1,
    output wire [6:0]  my_memory2,
    output wire [6:0]  my_memory3,
    output wire [6:0]  my_memory4,
    output wire [6:0]  my_memory5,
    output wire [6:0]  my_memory6,
    output wire [6:0]  my_memory7,
    output wire [6:0]  my_memory8
);

reg [6:0] memory [7:0];
reg [2:0] idx = 0;

wire [55:0] magic = {
    {memory[0], memory[5]},
    {memory[6], memory[2]},
    {memory[4], memory[3]},
    {memory[7], memory[1]}
};

wire [55:0] kittens = { magic[9:0],  magic[41:22], magic[21:10], magic[55:42] };
assign open_safe = kittens == 56'd3008192072309708;
assign my_test = kittens;
assign my_test2 = magic;
assign my_memory1 = memory[0];
assign my_memory2 = memory[1];
assign my_memory3 = memory[2];
assign my_memory4 = memory[3];
assign my_memory5 = memory[4];
assign my_memory6 = memory[5];
assign my_memory7 = memory[6];
assign my_memory8 = memory[7];

always_ff @(posedge clk) begin
    memory[idx] <= data;
    idx <= idx + 5;
end

endmodule

