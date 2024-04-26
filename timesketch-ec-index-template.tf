locals {
  # Elastic field types https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-types.html
  mappings = jsonencode({
    # Timesketch mandatory fields
    properties = {
      datetime = {
        type = "date"
      }
      timestamp_desc = {
        type = "text"
        fields = {
          keyword = {
            type = "keyword"
          }
        }
      }
      data_type = {
        type = "text"
        fields = {
          keyword = {
            type = "keyword"
          }
        }
      }
      timesketch_label = {
        type = "nested"
        properties = {
          name = {
            type = "text"
            fields = {
              keyword = {
                type         = "keyword"
                ignore_above = 256
              }
            }
          }
          sketch_id = {
            type = "long"
          }
          user_id = {
            type = "long"
          }
        }
      }
      __ts_timeline_id = {
        type = "long"
      }
    }

    # The other fields are mapped to an object or text.
    dynamic_templates = [
      {
        object = {
          match_mapping_type = "object"
          mapping = {
            type = "object"
          }
        }
      },
      {
        string = {
          match_mapping_type = "*"
          mapping = {
            type = "text"
            fields = {
              keyword = {
                type         = "keyword"
                ignore_above = 256
              }
            }
          }
        }
      }
    ]
  })
}
