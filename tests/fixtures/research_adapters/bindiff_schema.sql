-- UNVERIFIED: hand-written from the documented BinDiff 2/3 result schema, not exported by BinDiff.
CREATE TABLE function (id INTEGER PRIMARY KEY, address1 BIGINT, name1 TEXT, address2 BIGINT, name2 TEXT,
  similarity REAL, confidence REAL, flags INTEGER, algorithm SMALLINT, evaluate BOOLEAN, commentsported BOOLEAN,
  basicblocks INTEGER, edges INTEGER, instructions INTEGER);
INSERT INTO function (address1, name1, address2, name2, similarity, confidence) VALUES
  (4096, 'Parser::parse_header', 4096, 'Parser::parse_header', 0.41, 0.90),
  (8192, 'checksum', 8200, 'checksum', 0.93, 0.99),
  (12288, 'alpha', 12288, 'alpha', 0.93, 0.70),
  (16384, 'same_fn', 16384, 'same_fn', 1.0, 1.0),
  (20480, '', 20480, 'only_new_name', 0.80, 0.5),
  (24576, '', 24576, '', 0.10, 0.5);
