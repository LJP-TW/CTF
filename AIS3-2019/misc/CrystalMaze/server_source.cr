require "./secret"

def run(client : TCPSocket)
  spawn do
    sleep 5.seconds
    begin
      client.puts "timeout"
    rescue
    end
    client.close
  end

  begin
    client.puts "Bonjour. You're in a #{SIZE}x#{SIZE} crystal maze."
    client.puts "To take a step, enter \"up\", \"down\", \"left\", or \"right\"."

    x = 0
    y = 0

    loop do
      client.send "move: "

      case client.gets
      when "up"
        y += 1
      when "down"
        y -= 1
      when "left"
        x -= 1
      when "right"
        x += 1
      else
        client.puts "?"
        break
      end

      if !((0 <= x < SIZE) && (0 <= y < SIZE))
        client.puts "wall"
        break
      end

      case MAZE[x][y]
      when 0
        client.puts "ok"
      when 1
        client.puts "wall"
        break
      when 2
        client.puts FLAG
        break
      end

    end

  rescue
  end

  client.close
end


while client = SERVER.accept?.as TCPSocket
  spawn run client
end
