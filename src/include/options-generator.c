/*
     This file is part of libmicrohttpd
     Copyright (C) 2024 Christian Grothoff (and other contributing authors)

     This library is free software; you can redistribute it and/or
     modify it under the terms of the GNU Lesser General Public
     License as published by the Free Software Foundation; either
     version 2.1 of the License, or (at your option) any later version.

     This library is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Lesser General Public License for more details.

     You should have received a copy of the GNU Lesser General Public
     License along with this library; if not, write to the Free Software
     Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/
/**
 * @file options-generator.c
 * @brief Generates code based on JSON-converted Recutils database
 * @author Christian Grothoff
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <jansson.h>
#include <sys/stat.h>

static FILE *f;

static char *category;

typedef void
(*Callback) (const char *name,
             unsigned int value,
             const char *comment,
             const char *type,
             const char *conditional,
             json_t *args,
             json_t *descs);


static void
iterate (json_t *input,
         Callback cb)
{
  const char *name;
  json_t *obj;

  json_object_foreach (input, name, obj)
  {
    unsigned int value
      = json_integer_value (json_object_get (obj,
                                             "Value"));
    const char *comment
      = json_string_value (json_object_get (obj,
                                            "Comment"));
    const char *type
      = json_string_value (json_object_get (obj,
                                            "Type"));
    const char *conditional
      = json_string_value (json_object_get (obj,
                                            "Conditional"));
    json_t *args
      = json_object_get (obj,
                         "Arguments");
    json_t *descs
      = json_object_get (obj,
                         "Descriptions");

    if (0 == strcmp ("end",
                     name))
      continue;
    cb (name,
        value,
        comment,
        type,
        conditional,
        args,
        descs);
  }
}


static void
check (const char *name,
       unsigned int value,
       const char *comment,
       const char *type,
       const char *conditional,
       json_t *args,
       json_t *descs)
{
  if (json_array_size (args) != json_array_size (descs))
  {
    fprintf (stderr,
             "Mismatch between descriptions and arguments for `%s'\n",
             name);
    exit (2);
  }
  if ( (NULL == type) &&
       ( (NULL == args) ||
         (1 != json_array_size (args)) ) )
  {
    fprintf (stderr,
             "Type and argument missing for `%s' and not exactly 1 argument\n",
             name);
    exit (2);
  }
  for (unsigned int i = 0; i<json_array_size (args); i++)
  {
    const char *arg = json_string_value (json_array_get (args,
                                                         0));

    if (NULL == (strrchr (arg, ' ')))
    {
      fprintf (stderr,
               "Mandatory space missing in argument%u of `%s'\n",
               i,
               name);
      exit (2);
    }
  }
  if (NULL != strchr (name, ' '))
  {
    fprintf (stderr,
             "Spaces are not allowed in names, found one in `%s'\n",
             name);
    exit (2);
  }
}


static char *
indent (char *pfx,
        const char *input)
{
  char *ret = strdup (input);
  char *xfx = strdup (pfx);
  char *off;
  size_t pos = 0;

  while ( (strlen (xfx) > 0) &&
          (isspace (xfx[strlen (xfx) - 1])) )
    xfx[strlen (xfx) - 1] = '\0';
  while (NULL != (off = strchr (ret + pos, '\n')))
  {
    char *tmp;

    asprintf (&tmp,
              "%.*s\n%s%s",
              (int) (off - ret),
              ret,
              (off[1] == '\n')
              ? xfx
              : pfx,
              off + 1);
    pos = (off - ret) + strlen (pfx) + 1;
    free (ret);
    ret = tmp;
  }
  return ret;
}


static char *
uppercase (const char *input)
{
  char *ret = strdup (input);

  for (size_t i = 0; '\0' != ret[i]; i++)
    ret[i] = toupper (ret[i]);
  return ret;
}


static char *
capitalize (const char *input)
{
  char *ret = strdup (input);

  ret[0] = toupper (ret[0]);
  return ret;
}


static char *
lowercase (const char *input)
{
  char *ret = strdup (input);

  for (size_t i = 0; '\0' != ret[i]; i++)
    ret[i] = tolower (ret[i]);
  return ret;
}


static void
dump_enum (const char *name,
           unsigned int value,
           const char *comment,
           const char *type,
           const char *conditional,
           json_t *args,
           json_t *descs)
{
  printf ("  /**\n   * %s\n   */\n  MHD_%c_O_%s = %u\n  ,\n\n",
          indent ("   * ", comment),
          (char) toupper (*category),
          uppercase (name),
          value);
}


static const char *
var_name (const char *arg)
{
  const char *space;

  space = strrchr (arg, ' ');
  while ('*' == space[1])
    space++;
  return space + 1;
}


static void
dump_union_members (const char *name,
                    unsigned int value,
                    const char *comment,
                    const char *type,
                    const char *conditional,
                    json_t *args,
                    json_t *descs)
{
  if (NULL == type)
    return;
  if (1 >= json_array_size (args))
    return;

  printf ("/**\n * Data for #MHD_%c_O_%s\n */\n%s\n{\n",
          (char) toupper (*category),
          uppercase (name),
          type);
  for (unsigned int i = 0; i<json_array_size (args); i++)
  {
    const char *arg = json_string_value (json_array_get (args,
                                                         i));
    const char *desc = json_string_value (json_array_get (descs,
                                                          i));
    const char *vn = var_name (arg);

    printf ("  /**\n   * %s\n   */\n  %.*sv_%s;\n\n",
            indent ("   * ",
                    desc),
            (int) (vn - arg),
            arg,
            vn);
  }
  printf ("};\n\n");
}


static void
dump_union (const char *name,
            unsigned int value,
            const char *comment,
            const char *type,
            const char *conditional,
            json_t *args,
            json_t *descs)
{
  const char *xcomment = NULL;

  xcomment = json_string_value (json_array_get (descs,
                                                0));
  fprintf (f,
           "  /**\n"
           "   * Value for #MHD_%c_O_%s.%s%s\n"
           "   */\n",
           (char) toupper (*category),
           uppercase (name),
           NULL != xcomment
          ? "\n   * "
          : "",
           NULL != xcomment
          ? indent ("   * ", xcomment)
          : "");
  if (NULL != type)
  {
    fprintf (f,
             "  %s %s;\n",
             type,
             lowercase (name));
  }
  else
  {
    const char *arg = json_string_value (json_array_get (args,
                                                         0));
    const char *vn = var_name (arg);

    fprintf (f,
             "  %.*s%s;\n",
             (int) (vn - arg),
             arg,
             lowercase (name));
  }
  fprintf (f,
           "\n");
}


static void
dump_struct (const char *name,
             unsigned int value,
             const char *comment,
             const char *type,
             const char *conditional,
             json_t *args,
             json_t *descs)
{
  if (NULL != conditional)
    fprintf (f,
             "#ifdef HAVE_%s",
             uppercase (conditional));
  dump_union (name,
              value,
              comment,
              type,
              conditional,
              args,
              descs);
  if (NULL != conditional)
    fprintf (f,
             "#endif\n");
  fprintf (f,
           "\n");
}


static void
dump_option_macros (const char *name,
                    unsigned int value,
                    const char *comment,
                    const char *type,
                    const char *conditional,
                    json_t *args,
                    json_t *descs)
{
  size_t off;
  json_t *pos;

  printf (
    "/**\n * %s\n",
    indent (" * ", comment));
  json_array_foreach (descs, off, pos)
  {
    const char *arg = json_string_value (json_array_get (args,
                                                         off));
    const char *desc = json_string_value (pos);
    const char *vn = var_name (arg);

    printf (" * @param %s %s\n",
            vn,
            indent (" *   ",
                    desc));
  }
  if (0 == json_array_size (descs))
    printf (" * @param val the value of the parameter");
  printf (" * @return structure with the requested setting\n */\n");
  printf ("#  define MHD_%c_OPTION_%s(",
          (char) toupper (*category),
          uppercase (name));
  if (0 == json_array_size (args))
    printf ("val");
  else
    for (unsigned int i = 0; i<json_array_size (args); i++)
    {
      if (0 != i)
        printf (",");
      printf ("%s",
              var_name (
                json_string_value (
                  json_array_get (args,
                                  i))));
    }
  printf (") \\\n"
          "        MHD_NOWARN_COMPOUND_LITERALS_ \\\n"
          "          (const struct MHD_%sOptionAndValue) \\\n"
          "        { \\\n"
          "          .opt = MHD_%c_O_%s,  \\\n",
          capitalize (category),
          (char) toupper (*category),
          uppercase (name));
  if (0 == json_array_size (args))
    printf ("          .val.%s = (val) \\\n",
            lowercase (name));
  else
    for (unsigned int i = 0; i<json_array_size (args); i++)
    {
      const char *vn = var_name (
        json_string_value (
          json_array_get (args,
                          i)));

      if (1 < json_array_size (args))
        printf ("          .val.%s.v_%s = (%s)%s \\\n",
                lowercase (name),
                vn,
                vn,
                (i < json_array_size (args) - 1)
              ? ","
              : "");
      else
        printf ("          .val.%s = (%s)%s \\\n",
                lowercase (name),
                vn,
                (i < json_array_size (args) - 1)
                ? ","
                : "");
    }

  printf ("        } \\\n"
          "        MHD_RESTORE_WARN_COMPOUND_LITERALS_\n");
}


static void
dump_option_static_functions (const char *name,
                              unsigned int value,
                              const char *comment,
                              const char *type,
                              const char *conditional,
                              json_t *args,
                              json_t *descs)
{
  size_t off;
  json_t *pos;

  printf (
    "\n"
    "/**\n * %s\n",
    indent (" * ", comment));
  json_array_foreach (descs, off, pos)
  {
    const char *arg = json_string_value (json_array_get (args,
                                                         off));
    const char *desc = json_string_value (pos);
    const char *vn = var_name (arg);

    printf (" * @param %s %s\n",
            vn,
            indent (" *   ",
                    desc));
  }
  if (0 == json_array_size (descs))
    printf (" * @param val the value of the parameter");
  printf (" * @return structure with the requested setting\n */\n");
  printf ("static MHD_INLINE struct MHD_%sOptionAndValue\n"
          "MHD_%c_OPTION_%s (\n",
          category,
          (char) toupper (*category),
          uppercase (name));
  if (0 == json_array_size (args))
    printf ("  %s val",
            NULL != type
            ? type
            : json_string_value (
              json_array_get (args,
                              0)));
  else
    for (unsigned int i = 0; i<json_array_size (args); i++)
    {
      const char *arg
        = json_string_value (
            json_array_get (args,
                            i));
      const char *vn
        = var_name (arg);
      if (0 != i)
        printf (",\n");
      printf ("  %.*s%s",
              (int) (vn - arg),
              arg,
              vn);
    }
  printf (
    "\n"
    "  )\n"
    "{\n"
    "  struct MHD_%sOptionAndValue opt_val;\n\n"
    "  opt_val.opt = MHD_%c_O_%s;\n",
    capitalize (category),
    (char) toupper (*category),
    uppercase (name));
  if (0 == json_array_size (args))
    printf ("  opt_val.val.%s = (val); \\\n",
            lowercase (name));
  else
    for (unsigned int i = 0; i<json_array_size (args); i++)
    {
      const char *vn = var_name (
        json_string_value (
          json_array_get (args,
                          i)));

      if (1 < json_array_size (args))
        printf ("  opt_val.val.%s.v_%s = %s;\n",
                lowercase (name),
                vn,
                vn);
      else
        printf ("  opt_val.val.%s = %s;\n",
                lowercase (name),
                vn);
    }
  printf ("\n  return opt_val;\n}\n\n");
}


static void
dump_option_documentation_functions (const char *name,
                                     unsigned int value,
                                     const char *comment,
                                     const char *type,
                                     const char *conditional,
                                     json_t *args,
                                     json_t *descs)
{
  size_t off;
  json_t *pos;

  fprintf (f,
           "/**\n * %s\n",
           indent (" * ", comment));
  json_array_foreach (descs, off, pos)
  {
    const char *arg = json_string_value (json_array_get (args,
                                                         off));
    const char *desc = json_string_value (pos);
    const char *vn = var_name (arg);

    fprintf (f, " * @param %s %s\n",
             vn,
             indent (" *   ",
                     desc));
  }
  if (0 == json_array_size (descs))
    fprintf (f, " * @param val the value of the parameter");
  fprintf (f, " * @return structure with the requested setting\n */\n");
  fprintf (f,"struct MHD_%sOptionAndValue\n"
           "MHD_%c_OPTION_%s (\n",
           capitalize (category),
           (char) toupper (*category),
           uppercase (name));
  if (0 == json_array_size (args))
    fprintf (f,
             "  %s val",
             NULL != type
             ? type
             : json_string_value (
               json_array_get (args,
                               0)));
  else
    for (unsigned int i = 0; i<json_array_size (args); i++)
    {
      const char *arg
        = json_string_value (
            json_array_get (args,
                            i));
      const char *vn
        = var_name (arg);
      if (0 != i)
        fprintf (f, ",\n");
      fprintf (f,
               "  %.*s%s",
               (int) (vn - arg),
               arg,
               vn);
    }
  fprintf (f,
           "\n  );\n\n");
}


static void
dump_option_set_switch (const char *name,
                        unsigned int value,
                        const char *comment,
                        const char *type,
                        const char *conditional,
                        json_t *args,
                        json_t *descs)
{
  if (NULL != conditional)
    fprintf (f,
             "#ifdef HAVE_%s",
             uppercase (conditional));
  fprintf (f,
           "    case MHD_%c_OPTION_%s:\n",
           (char) toupper (*category),
           uppercase (name));
  if (0 == json_array_size (args))
    fprintf (f,
             "      %s->settings.%s = option->val.%s;\n",
             category,
             lowercase (name),
             lowercase (name));
  else
    for (unsigned int i = 0; i<json_array_size (args); i++)
    {
      const char *vn = var_name (
        json_string_value (
          json_array_get (args,
                          i)));

      if (1 < json_array_size (args))
        fprintf (f,
                 "      %s->settings.%s.v_%s = option->val.%s.v_%s;\n",
                 category,
                 lowercase (name),
                 vn,
                 lowercase (name),
                 vn);
      else
        fprintf (f,
                 "      %s->settings.%s = option->val.%s;\n",
                 category,
                 lowercase (name),
                 lowercase (name));
    }
  fprintf (f,
           "      continue;\n");
  if (NULL != conditional)
    fprintf (f,
             "#endif\n");
}


int
main (int argc,
      char **argv)
{
  json_t *j;
  json_error_t err;

  if (argc < 2)
  {
    fprintf (stderr,
             "Category argument required\n");
    return 3;
  }
  category = argv[1];

  {
    char *fn;

    asprintf (&fn,
              "%c_options.json",
              *category);
    j = json_load_file (fn, 0, &err);
    if (NULL == j)
    {
      fprintf (stderr,
               "Failed to parse %s: %s at %d:%d\n",
               fn,
               err.text,
               err.line,
               err.column);
      free (fn);
      return 2;
    }
    free (fn);
  }
  iterate (j,
           &check);

  /* Generate enum MHD_${CATEGORY}Option */
  printf ("/**\n"
          " * The options (parameters) for MHD %s\n"
          " */\n"
          "enum MHD_FIXED_ENUM_APP_SET_ MHD_%sOption\n"
          "{",
          category,
          capitalize (category));
  printf ("  /**\n"
          "   * Not a real option.\n"
          "   * Should not be used directly.\n"
          "   * This value indicates the end of the list of the options.\n"
          "   */\n"
          "  MHD_%c_O_END = 0\n"
          "  ,\n\n",
          (char) toupper (*category));
  iterate (j,
           &dump_enum);
  printf ("  /**\n"
          "   * The sentinel value.\n"
          "   * This value enforces specific underlying integer type for the enum.\n"
          "   * Do not use.\n"
          "   */\n"
          "  MHD_%c_O_SENTINEL = 65535\n\n",
          (char) toupper (*category));
  printf ("};\n\n");
  iterate (j,
           &dump_union_members);

  /* Generate union MHD_${CATEGORY}OptionValue */
  printf ("/**\n"
          " * Parameters for MHD %s options\n"
          " */\n"
          "union MHD_%sOptionValue\n"
          "{\n",
          category,
          capitalize (category));
  f = stdout;
  iterate (j,
           &dump_union);
  f = NULL;
  printf ("};\n\n");

  printf ("\n"
          "struct MHD_%sOptionAndValue\n"
          "{\n"
          "  /**\n"
          "   * The %s configuration option\n"
          "   */\n"
          "  enum MHD_%sOption opt;\n\n"
          "  /**\n"
          "   * The value for the @a opt option\n"
          "   */\n"
          "  union MHD_%sOptionValue val;\n"
          "};\n\n",
          capitalize (category),
          category,
          capitalize (category),
          capitalize (category));
  printf (
    "#if defined(MHD_USE_COMPOUND_LITERALS) && defined(MHD_USE_DESIG_NEST_INIT)\n");
  iterate (j,
           &dump_option_macros);
  printf (
    "\n"
    "/**\n"
    " * Terminate the list of the options\n"
    " * @return the terminating object of struct MHD_%sOptionAndValue\n"
    " */\n"
    "#  define MHD_%c_OPTION_TERMINATE() \\\n"
    "        MHD_NOWARN_COMPOUND_LITERALS_ \\\n"
    "          (const struct MHD_%sOptionAndValue) \\\n"
    "        { \\\n"
    "          .opt = (MHD_%c_O_END) \\\n"
    "        } \\\n"
    "        MHD_RESTORE_WARN_COMPOUND_LITERALS_\n\n",
    capitalize (category),
    (char) toupper (*category),
    capitalize (category),
    (char) toupper (*category));

  printf (
    "#else /* !MHD_USE_COMPOUND_LITERALS || !MHD_USE_DESIG_NEST_INIT */\n");
  printf ("MHD_NOWARN_UNUSED_FUNC_");
  iterate (j, &dump_option_static_functions);
  printf ("\n/**\n"
          " * Terminate the list of the options\n"
          " * @return the terminating object of struct MHD_%sOptionAndValue\n"
          " */\n"
          "static MHD_INLINE struct MHD_%sOptionAndValue\n"
          "MHD_%c_OPTION_TERMINATE (void)\n"
          "{\n"
          "  struct MHD_%sOptionAndValue opt_val;\n\n"
          "  opt_val.opt = MHD_%c_O_END;\n\n"
          "  return opt_val;\n"
          "}\n\n\n",
          capitalize (category),
          capitalize (category),
          (char) toupper (*category),
          capitalize (category),
          (char) toupper (*category));

  printf ("MHD_RESTORE_WARN_UNUSED_FUNC_\n");
  printf (
    "#endif /* !MHD_USE_COMPOUND_LITERALS || !MHD_USE_DESIG_NEST_INIT */\n");

  {
    char *doc_in;

    asprintf (&doc_in,
              "microhttpd2_inline_%s_documentation.h.in",
              category);
    (void) unlink (doc_in);
    f = fopen (doc_in, "w");
    if (NULL == f)
    {
      fprintf (stderr,
               "Failed to open `%s'\n",
               doc_in);
      return 2;
    }
    fprintf (f,
             "/* Beginning of generated code documenting how to use options.\n"
             "   You should treat the following functions *as if* they were\n"
             "   part of the header/API. The actual declarations are more\n"
             "   complex, so these here are just for documentation!\n"
             "   We do not actually *build* this code... */\n"
             "#if 0\n\n");
    iterate (j,
             &dump_option_documentation_functions);
    fprintf (f,
             "/* End of generated code documenting how to use options */\n#endif\n\n");
    fclose (f);
    chmod (doc_in, S_IRUSR | S_IRGRP | S_IROTH);
  }

  {
    char *so_c;

    asprintf (&so_c,
              "../mhd2/%s_set_options.c",
              category);
    (void) unlink (so_c);
    f = fopen (so_c, "w");
    if (NULL == f)
    {
      fprintf (stderr,
               "Failed to open `%s'\n",
               so_c);
      return 2;
    }
    fprintf (f,
             "/* This is generated code, it is still under LGPLv3+.\n"
             "   Do not edit directly! */\n"
             "/* *INDENT-OFF* */\n"
             "/**\n"
             "/* @file %s_set_options.c\n"
             "/* @author %s-options-generator.c\n"
             " */\n\n"
             "#include \"microhttpd2.h\"\n"
             "#include \"internal.h\"\n\n"
             "enum MHD_StatusCode\n"
             "MHD_%s_set_options (\n"
             "  struct MHD_%s *%s,\n"
             "  const struct MHD_%sOptionAndValue *options,\n"
             "  size_t options_max_num)\n"
             "{\n",
             category,
             category,
             category,
             capitalize (category),
             category,
             capitalize (category));
    fprintf (f,
             "  for (size_t i=0;i<options_max_num;i++)\n"
             "  {\n"
             "    switch (options[i].opt) {\n");
    iterate (j,
             &dump_option_set_switch);
    fprintf (f,
             "    }\n"
             "    return MHD_SC_OPTION_UNSUPPORTED;\n"
             "  }\n"
             "  return MHD_SC_OK;\n");
    fprintf (f,
             "}\n");

    fclose (f);
    chmod (so_c, S_IRUSR | S_IRGRP | S_IROTH);
    free (so_c);
  }

  {
    char *do_h;

    asprintf (&do_h,
              "../mhd2/%s_options.h",
              category);
    (void) unlink (do_h);
    f = fopen (do_h, "w");
    if (NULL == f)
    {
      fprintf (stderr,
               "Failed to open `%s'\n",
               do_h);
      return 2;
    }
    fprintf (f,
             "/* This is generated code, it is still under LGPLv3+.\n"
             "   Do not edit directly! */\n"
             "/* *INDENT-OFF* */\n"
             "/**\n"
             "/* @file %s_options.h\n"
             "/* @author %s-options-generator.c\n"
             " */\n\n"
             "#include \"microhttpd2.h\"\n"
             "#include \"internal.h\"\n\n"
             "struct %sOptions {\n",
             category,
             category,
             capitalize (category));
    iterate (j,
             &dump_struct);
    fprintf (f,
             "};\n");
    fclose (f);
    chmod (do_h, S_IRUSR | S_IRGRP | S_IROTH);
    free (do_h);
  }


  json_decref (j);
  return 0;
}
