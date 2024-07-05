locals {
  # Elastic field types https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-types.html
  mappings = jsonencode({
    # Timesketch mandatory fields
    properties = {
      datetime = {
        type = "date"
      }
      timestamp_desc = {
        type = "keyword"
      }
      data_type = {
        type = "keyword"
      }
      timesketch_label = {
        type = "nested"
        properties = {
          name = {
            type = "keyword"
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

    # The other fields are mapped to as object or wildcard.
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
        wildcard = {
          match_mapping_type = "*"
          mapping = {
            type = "wildcard"
          }
        }
      }
    ]
  })
}
