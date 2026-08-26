class Api
  def serve
    process
  end

  def unused_helper
  end

  private

  def process
    not_done
  end

  def not_done
    raise NotImplementedError
  end
end
